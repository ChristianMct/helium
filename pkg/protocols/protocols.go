// package protocols implements the MHE protocol execution.
// It uses Lattigo as the underlying MHE library.
package protocols

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v4/drlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"golang.org/x/crypto/blake2b"
)

const (
	protocolLogging     = false // whether to log events in protocol execution
	hidHashHexCharCount = 4     // number of hex characters display in the human-readable id
)

// Type is an enumerated type for protocol types.
type Type uint

const (
	// Unknown is the default value for the protocol type.
	Unknown Type = iota
	// SKG is the secret-key generation protocol. // TODO: unsupported
	SKG
	// CKG is the collective public-key generation protocol.
	CKG
	// RKG is the relinearization key generation protocol.
	RKG
	// RKG_1 is the first round of the relinearization key generation protocol.
	RKG_1
	// RTG is the galois key generation protocol.
	RTG
	// CKS is the collective key-switching protocol. // TODO: unsupported
	CKS
	// DEC is the decryption protocol.
	DEC
	// PCKS is the collective public-key switching protocol. // TODO: unsupported
	PCKS
)

// Signature is a protocol prototype. In analogy to a function signature, it
// describes the type of the protocol and the arguments it expects.
type Signature struct {
	Type Type
	Args map[string]string
}

// Descriptor is a protocol instance. It is a complete description of
// a protocol's execution, by complementing the Signature with a role
// assignment.
//
// Multiple protocol instances can share the same signature, but have
// different descriptors (e.g., in the case of a failure).
// However, a protocol instance is uniquely identified by its descriptor.
type Descriptor struct {
	Signature
	Participants []pkg.NodeID
	Aggregator   pkg.NodeID
}

// ID is a type for protocol IDs. Protocol IDs are unique identifiers for
// a protocol instance. Since a protocol instance is uniquely identified by
// its descriptor, the ID is derived from the descriptor.
type ID string

// Input is a type for protocol inputs.
type Input interface{}

// Output is a type for protocol outputs.
// It contains the result of the protocol execution or an error if the
// protocol execution has failed.
type Output struct {
	Result interface{}
	Error  error
}

// Share is a type for the nodes' protocol shares.
type Share struct {
	ShareMetadata
	MHEShare LattigoShare
}

// ShareMetadata retains the necessary information for the framework to
// identify the share and the protocol it belongs to.
type ShareMetadata struct {
	ProtocolID   ID
	ProtocolType Type
	From         utils.Set[pkg.NodeID]
}

// CRP is a type for the common reference polynomials used in the
// key generation protocol. A CRP is a polynomial that is sampled
// uniformly at random, yet is the same for all nodes. CRPs are
// expanded from the session's public seed.
type CRP interface{}

// ReceiverKey is a type for the output keys in the key switching
// protocols. Depending on the type of protocol, the receiver key
// can be either a *rlwe.SecretKey (collective key-switching, CKS)
// or a *rlwe.PublicKey (collective public-key switching, PCKS).
type ReceiverKey interface{}

// AggregationOutput is a type for the output of a protocol's aggregation
// step. In addition to the protocol's descriptor, it contains either
// the aggregated share or an error if the aggregation has failed.
type AggregationOutput struct {
	Descriptor Descriptor
	Share      Share
	Error      error
}

// Instance is an interface for running protocol instances.
//
// Note: protocol instances were executed by the services directly
// in previous versions of the code, hence the existance of this
// interface.
type Instance interface {
	// ID returns the ID of the protocol instance.
	ID() ID
	// HID returns the human-readable (truncated) ID of the protocol instance.
	HID() string
	// Descriptor returns the protocol descriptor of the protocol instance.
	Descriptor() Descriptor
	// AllocateShare returns a newly allocated share for the protocol instance.
	AllocateShare() Share
	// GenShare is called by the session nodes to generate their share in the protocol instance,
	// storing the result in the provided share. // TODO update
	GenShare(*rlwe.SecretKey, *Share) error
	// Aggregate is called by the aggregator node to aggregate the shares of the protocol instance.
	// The method aggregates the shares received in the provided incoming channel in the background,
	// and sends the aggregated share to the returned channel when the aggregation has completed.
	// Upon receiving the aggregated share, the caller must check the Error field of the aggregation
	// output to determine whether the aggregation has failed.
	// The aggregation can be cancelled by cancelling the context.
	// If the context is cancelled or the incoming channel is closed before the aggregation has completed,
	// the method sends the aggregation output with the corresponding error to the returned channel.
	// The method panics if called by a non-aggregator node.
	Aggregate(ctx context.Context, incoming <-chan Share) <-chan AggregationOutput
	// HasShareFrom returns whether the protocol instance has already recieved a share from the specified node.
	HasShareFrom(pkg.NodeID) bool
	// Output computes the output of the protocol instance from the aggregation output.
	Output(agg AggregationOutput) chan Output
}

// NewProtocol creates a new protocol instance from the provided protocol descriptor, session and inputs.
func NewProtocol(pd Descriptor, sess *pkg.Session, inputs ...Input) (Instance, error) {
	switch pd.Signature.Type {
	case CKG, RTG, RKG_1, RKG:
		return NewKeygenProtocol(pd, sess, inputs...)
	case CKS, DEC, PCKS:
		return NewKeyswitchProtocol(pd, sess, inputs...)
	default:
		return nil, fmt.Errorf("unknown protocol type: %s", pd.Signature.Type)
	}
}

// patProtocol is a base struct for patProtocol instances.
type patProtocol struct {
	pd   Descriptor
	id   ID
	hid  string
	self pkg.NodeID

	pubrand, privrand blake2b.XOF

	proto MHEProtocol

	// aggregator only
	agg *shareAggregator
}

func newPATProtocol(pd Descriptor, sess *pkg.Session) (*patProtocol, error) {

	if len(pd.Participants) < sess.Threshold {
		return nil, fmt.Errorf("invalid protocol descriptor: not enough participant to execute protocol: %d < %d", len(pd.Participants), sess.Threshold)
	}

	for _, p := range pd.Participants {
		if !sess.Contains(p) {
			return nil, fmt.Errorf("participant %s not in session", p)
		}
	}

	p := &patProtocol{id: pd.ID(), hid: pd.HID(), pd: pd, self: sess.NodeID}

	// initilize the randomness sources from the session
	p.pubrand = GetProtocolPublicRandomness(pd, sess)
	var err error
	if p.IsParticipant() {
		p.privrand = GetProtocolPrivateRandomness(pd, sess)
	}

	// intialize the protocol instance
	p.proto, err = NewMHEProtocol(pd.Signature, sess.Params.Parameters)
	if err != nil {
		return nil, err
	}

	if p.IsAggregator() {
		p.agg = newShareAggregator(pd, p.proto.AllocateShare(), p.proto.AggregatedShares) // TODO: could cache the shares
	}

	if (p.pd.Type == RKG_1 || p.pd.Type == RKG) && p.IsParticipant() {
		p.proto.(*RKGProtocol).ephSk, err = sess.GetRLKEphemeralSecretKey()
		if err != nil {
			return nil, err
		}
	}

	return p, nil
}

func (p *patProtocol) Aggregate(ctx context.Context, incoming <-chan Share) <-chan AggregationOutput {

	if !p.IsAggregator() {
		panic(fmt.Errorf("node is not the aggregator"))
	}

	aggOutChan := make(chan AggregationOutput, 1)
	go func() {
		var aggOut AggregationOutput
		var err error
		var done bool
		for !done {
			// aggregates recieved shares until the aggregation completes,
			// the incoming is closed or the context is cancelled.
			select {
			case share, more := <-incoming:
				if !more {
					done = true
					err = fmt.Errorf("incoming channel closed before completing aggregation")
					continue
				}
				done, err = p.agg.PutShare(share)
				p.Logf("new share from %s, done=%v, err=%v", share.From, done, err)
				if err != nil {
					done = true // stops aggregating on error
				}
			case <-ctx.Done():
				err = fmt.Errorf("context cancelled before completing aggregation: %s", ctx.Err())
				done = true
			}
		}

		aggOut.Descriptor = p.pd
		aggOut.Share.ProtocolID = p.id
		aggOut.Share.ProtocolType = p.pd.Type
		if err == nil {
			aggOut.Share = p.agg.share
			p.Logf("[%s] aggregation done", p.HID())
		} else {
			aggOut.Error = err
			p.Logf("[%s] aggregation error: %s", p.HID(), err)
		}
		aggOutChan <- aggOut
		close(aggOutChan)
	}()

	p.Logf("[%s] aggregating shares", p.HID())

	return aggOutChan
}

func (p *patProtocol) HID() string {
	return p.hid
}

var typeToString = []string{"Unknown", "SKG", "CKG", "RKG", "RKG_1", "RTG", "CKS", "DEC", "PCKS"}

func (t Type) String() string {
	if int(t) > len(typeToString) {
		t = 0
	}
	return typeToString[t]
}

func (t Type) Share() LattigoShare {
	switch t {
	case SKG:
		return &drlwe.ShamirSecretShare{}
	case CKG:
		return &drlwe.PublicKeyGenShare{}
	case RKG_1, RKG:
		return &drlwe.RelinearizationKeyGenShare{}
	case RTG:
		return &drlwe.GaloisKeyGenShare{}
	case CKS, DEC:
		return &drlwe.KeySwitchShare{}
	case PCKS:
		return &drlwe.PublicKeySwitchShare{}
	default:
		return nil
	}
}

func (t Type) IsSetup() bool {
	switch t {
	case CKG, RTG, RKG, RKG_1:
		return true
	default:
		return false
	}
}

func (t Type) IsCompute() bool {
	switch t {
	case DEC, PCKS:
		return true
	default:
		return false
	}
}

func (t Signature) String() string {
	args := make(sort.StringSlice, 0, len(t.Args))
	for argname, argval := range t.Args {
		args = append(args, fmt.Sprintf("%s=%s", argname, argval))
	}
	sort.Sort(args)
	return fmt.Sprintf("%s(%s)", t.Type, strings.Join(args, ","))
}

func (s Signature) Equals(other Signature) bool {
	if s.Type != other.Type {
		return false
	}
	for k, v := range s.Args {
		vOther, has := other.Args[k]
		if !has || v != vOther {
			return false
		}
	}
	return true
}

func (d Descriptor) ID() ID {
	return ID(fmt.Sprintf("%s-%x", d.Signature, HashOfPartList(d.Participants)))
}

func (d Descriptor) HID() string {
	h := HashOfPartList(d.Participants)
	return fmt.Sprintf("%s-%x", d.Signature, h[:hidHashHexCharCount>>1])
}

func (pd Descriptor) String() string {
	return fmt.Sprintf("{ID: %v, Type: %v, Args: %v, Aggregator: %v, Participants: %v}",
		pd.HID(), pd.Signature.Type, pd.Signature.Args, pd.Aggregator, pd.Participants)
}

func (pd Descriptor) MarshalBinary() (b []byte, err error) {
	return json.Marshal(pd)
}

func (pd *Descriptor) UnmarshalBinary(b []byte) (err error) {
	return json.Unmarshal(b, &pd)
}

func GetParticipants(sig Signature, onlineNodes utils.Set[pkg.NodeID], threshold int) ([]pkg.NodeID, error) {
	if len(onlineNodes) < threshold {
		return nil, fmt.Errorf("not enough online node")
	}

	available := onlineNodes.Copy()
	selected := utils.NewEmptySet[pkg.NodeID]()
	needed := threshold
	if sig.Type == DEC {
		target := pkg.NodeID(sig.Args["target"])
		selected.Add(target)
		available.Remove(target)
		needed--
	}
	selected.AddAll(utils.GetRandomSetOfSize(needed, available))
	return selected.Elements(), nil

}

func GetProtocolPublicRandomness(pd Descriptor, sess *pkg.Session) blake2b.XOF {
	xof, _ := blake2b.NewXOF(blake2b.OutputLengthUnknown, nil)
	_, err := xof.Write(sess.PublicSeed)
	if err != nil {
		panic(err)
	}
	_, err = xof.Write([]byte(pd.Signature.String()))
	if err != nil {
		panic(err)
	}
	hashPart := HashOfPartList(pd.Participants)
	_, err = xof.Write(hashPart[:])
	if err != nil {
		panic(err)
	}
	return xof
}

func GetProtocolPrivateRandomness(pd Descriptor, sess *pkg.Session) blake2b.XOF {
	xof := GetProtocolPublicRandomness(pd, sess)
	_, err := xof.Write(sess.PrivateSeed)
	if err != nil {
		panic(err)
	}
	return xof
}

func HashOfPartList(partList []pkg.NodeID) [32]byte {
	partListSorted := make(sort.StringSlice, len(partList))
	for i, nid := range partList {
		partListSorted[i] = string(nid)
	}
	if !sort.StringsAreSorted(partListSorted) {
		sort.Sort(partListSorted)
	}
	s := strings.Join(partListSorted, "")
	return blake2b.Sum256([]byte(s))
}
