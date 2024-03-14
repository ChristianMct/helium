// package protocols implements the MHE protocol execution.
// It uses Lattigo as the underlying MHE library.
package protocols

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/ldsec/helium"
	"github.com/ldsec/helium/session"
	"github.com/ldsec/helium/utils"
	"github.com/tuneinsight/lattigo/v4/drlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"golang.org/x/crypto/blake2b"
)

const (
	protocolLogging     = true // whether to log events in protocol execution
	hidHashHexCharCount = 4    // number of hex characters display in the human-readable id
)

// Type is an enumerated type for protocol types.
type Type uint

const (
	// Unspecified is the default value for the protocol type.
	Unspecified Type = iota
	// SKG is the secret-key generation protocol. // TODO: unsupported
	SKG
	// CKG is the collective public-key generation protocol.
	CKG
	// RKG_1 is the first round of the relinearization key generation protocol.
	RKG_1
	// RKG is the relinearization key generation protocol.
	RKG
	// RTG is the galois key generation protocol.
	RTG
	// CKS is the collective key-switching protocol. // TODO: unsupported
	CKS
	// DEC is the decryption protocol.
	DEC
	// PCKS is the collective public-key switching protocol. // TODO: unsupported
	PCKS
)

var typeToString = []string{"Unknown", "SKG", "CKG", "RKG_1", "RKG", "RTG", "CKS", "DEC", "PCKS"}

// Signature is a protocol prototype. In analogy to a function signature, it
// describes the type of the protocol and the arguments it expects.
type Signature struct {
	Type Type
	Args map[string]string
}

// Descriptor is a complete description of a protocol's execution (i.e., a protocol),
// by complementing the Signature with a role assignment.
//
// Multiple protocols can share the same signature, but have
// different descriptors (e.g., in the case of a failure).
// However, a protocol is uniquely identified by its descriptor.
type Descriptor struct {
	Signature
	Participants []helium.NodeID
	Aggregator   helium.NodeID
}

// ID is a type for protocol IDs. Protocol IDs are unique identifiers for
// a protocol. Since a protocol is uniquely identified by
// its descriptor, the ID is derived from the descriptor.
type ID string

// Input is a type for protocol inputs. Inputs are either:
//   - a CRP in the case of a key generation protocol  (CKG, RTG, RKG_1)
//   - an aggregated share from a previous round (RKG)
//   - a KeySwitchInput for the key-switching protocols (DEC, CKS, PCKS)
type Input interface{}

// CRP is a type for the common reference polynomials used in the
// key generation protocol. A CRP is a polynomial that is sampled
// uniformly at random, yet is the same for all nodes. CRPs are
// expanded from the session's public seed.
type CRP interface{}

// KeySwitchInput is a type for the inputs to the key-switching protocols.
type KeySwitchInput struct {
	// OutputKey is the target output key of the key-switching protocol,
	// it is a secret key (*rlwe.SecretKey) for the collective key-switching protocol (CKS)
	// and a public key (*rlwe.PublicKey) for the collective public-key switching protocol (PCKS).
	OutputKey ReceiverKey

	// InpuCt is the ciphertext to be re-encrpted under the output key.
	InpuCt *rlwe.Ciphertext
}

// Output is a type for protocol outputs.
// It contains the result of the protocol execution or an error if the
// protocol execution has failed.
type Output struct {
	Descriptor
	Result interface{}
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
	From         utils.Set[helium.NodeID]
}

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

// Protocol is a base struct for protocols.
type Protocol struct {
	pd   Descriptor
	id   ID
	hid  string
	self helium.NodeID

	pubrand, privrand blake2b.XOF

	proto mheProtocol

	// aggregator only
	agg *shareAggregator
}

// NewProtocol creates a new protocol from the provided protocol descriptor, session and inputs.
func NewProtocol(pd Descriptor, sess *session.Session) (*Protocol, error) {

	err := checkProtocolDescriptor(pd, sess)
	if err != nil {
		return nil, fmt.Errorf("invalid protocol descriptor: %w", err)
	}

	p := &Protocol{id: pd.ID(), hid: pd.HID(), pd: pd, self: sess.NodeID}

	// initilize the randomness sources from the session
	p.pubrand = GetProtocolPublicRandomness(pd, sess)
	if p.IsParticipant() {
		p.privrand = GetProtocolPrivateRandomness(pd, sess)
	}

	// intialize the protocol
	p.proto, err = newMHEProtocol(pd.Signature, sess.Params.Parameters)
	if err != nil {
		return nil, err
	}

	if p.IsAggregator() {
		p.agg = newShareAggregator(pd, p.proto.AllocateShare(), p.proto.AggregatedShares) // TODO: could cache the shares
	}

	// protocol-type-specific initialization
	switch {
	case (p.pd.Type == RKG_1 || p.pd.Type == RKG) && p.IsParticipant():
		p.proto.(*RKGProtocol).ephSk, err = sess.GetRLKEphemeralSecretKey()
		if err != nil {
			return nil, err
		}
	}

	return p, nil
}

// AllocateShare returns a newly allocated share for the protocol.
func (p *Protocol) AllocateShare() Share {
	return p.proto.AllocateShare()
}

// ReadCRP reads the common random polynomial for this protocol. Returns an error
// if called for a protocol that does not use CRP.
func (p *Protocol) ReadCRP() (CRP, error) {
	switch p.pd.Type {
	case CKG, RTG, RKG, RKG_1:
		return p.proto.ReadCRP(p.pubrand)
	}
	return nil, fmt.Errorf("protocol does not use CRP")
}

// GenShare is called by the session nodes to generate their share in the protocol,
// storing the result in the provided shareOut. The method returns an error if the node should
// not generate a share in the protocol.
func (p *Protocol) GenShare(sk *rlwe.SecretKey, in Input, shareOut *Share) error {

	if !p.IsParticipant() {
		return fmt.Errorf("node is not a participant")
	}

	if p.pd.Type == DEC && p.pd.Args["target"] == string(p.self) {
		return fmt.Errorf("decryption target should not generate a share")
	}

	p.Logf("[%s] generating share", p.pd.HID())
	shareOut.ProtocolID = p.id
	shareOut.From = utils.NewSingletonSet(p.self)
	shareOut.ProtocolType = p.pd.Type
	return p.proto.GenShare(sk, in, *shareOut)
}

// Aggregate is called by the aggregator node to aggregate the shares of the protocol.
// The method aggregates the shares received in the provided incoming channel in the background,
// and sends the aggregated share to the returned channel when the aggregation has completed.
// Upon receiving the aggregated share, the caller must check the Error field of the aggregation
// output to determine whether the aggregation has failed.
// The aggregation can be cancelled by cancelling the context.
// If the context is cancelled or the incoming channel is closed before the aggregation has completed,
// the method sends the aggregation output with the corresponding error to the returned channel.
// The method panics if called by a non-aggregator node.
func (p *Protocol) Aggregate(ctx context.Context, incoming <-chan Share) <-chan AggregationOutput {

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
				done, err = p.agg.put(share)
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

// Output computes the output of the protocol from the input and aggregation output, storing the result in out.
// Out must be a pointer to the type of the protocol's output, see AllocateOutput.
func (p *Protocol) Output(in Input, agg AggregationOutput, out interface{}) error {
	if agg.Error != nil {
		return fmt.Errorf("error at aggregation: %w", agg.Error)
	}

	if err := p.proto.Finalize(in, agg.Share, out); err != nil {
		return fmt.Errorf("error at output: %w", err)
	}
	p.Logf("finalized protocol")
	return nil
}

// ID returns the ID of the protocol.
func (p *Protocol) ID() ID {
	return p.id
}

// HID returns the human-readable (truncated) ID of the protocol.
func (p *Protocol) HID() string {
	return p.hid
}

// Descriptor returns the protocol descriptor of the protocol.
func (p *Protocol) Descriptor() Descriptor {
	return p.pd
}

// HasShareFrom returns whether the protocol has already recieved a share from the specified node.
func (p *Protocol) HasShareFrom(nid helium.NodeID) bool {
	return !p.agg.missing().Contains(nid)
}

// IsAggregator returns whether the node is the aggregator in the protocol.
func (p *Protocol) IsAggregator() bool {
	return p.pd.Aggregator == p.self || p.pd.Signature.Type == SKG
}

// IsParticipant returns whether the node is a participant in the protocol.
func (p *Protocol) IsParticipant() bool {
	return slices.Contains(p.pd.Participants, p.self)
}

// HasRole returns whether the node is an aggregator or a participant in the protocol.
func (p *Protocol) HasRole() bool {
	return p.IsAggregator() || p.IsParticipant()
}

// Logf logs a message
func (p *Protocol) Logf(msg string, v ...any) {
	if !protocolLogging {
		return
	}
	log.Printf("%s | [%s] %s\n", p.self, p.HID(), fmt.Sprintf(msg, v...))
}

func checkProtocolDescriptor(pd Descriptor, sess *session.Session) error {

	if len(pd.Participants) < sess.Threshold {
		return fmt.Errorf("invalid protocol descriptor: not enough participant to execute protocol: %d < %d", len(pd.Participants), sess.Threshold)
	}

	for _, p := range pd.Participants {
		if !sess.Contains(p) {
			return fmt.Errorf("participant %s not in session", p)
		}
	}

	target := helium.NodeID(pd.Signature.Args["target"])

	switch pd.Signature.Type {
	case CKS:
		return fmt.Errorf("standalone CKS protocol not supported yet") // TODO
	case DEC:
		if len(target) == 0 {
			return fmt.Errorf("should provide argument: target")
		}
		if sess.Contains(target) && !slices.Contains(pd.Participants, target) {
			return fmt.Errorf("a session target must be a protocol participant in DEC")
		}
		if !sess.Contains(target) && pd.Aggregator != target {
			return fmt.Errorf("target for protocol DEC should be a session node or the aggreator, was %s", target)
		}
	case PCKS:
		return fmt.Errorf("PCKS not supported yet") // TODO
	}

	return nil
}

// String returns the string representation of the protocol type.
func (t Type) String() string {
	if int(t) > len(typeToString) {
		t = 0
	}
	return typeToString[t]
}

// Share returns a lattigo share with the correct go type for the protocol type.
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

// IsSetup returns whether the protocol type is a key generation protocol.
func (t Type) IsSetup() bool {
	switch t {
	case CKG, RTG, RKG, RKG_1:
		return true
	default:
		return false
	}
}

// IsCompute returns whether the protocol type is
// a secret-key operation ciphertext operation.
func (t Type) IsCompute() bool {
	switch t {
	case DEC, PCKS:
		return true
	default:
		return false
	}
}

// String returns the string representation of the protocol signature.
// the arguments are alphabetically sorted by name so thtat the output
// is deterministic.
func (t Signature) String() string {
	args := make(sort.StringSlice, 0, len(t.Args))
	for argname, argval := range t.Args {
		args = append(args, fmt.Sprintf("%s=%s", argname, argval))
	}
	sort.Sort(args)
	return fmt.Sprintf("%s(%s)", t.Type, strings.Join(args, ","))
}

// Equals returns whether the signature is equal to the other signature,
// i.e., whether the protocol outputs are equivalent.
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

// ID returns the ID of the protocol, derived from the descriptor.
func (d Descriptor) ID() ID {
	return ID(fmt.Sprintf("%s-%x", d.Signature, partyListToString(d.Participants)))
}

// HID returns the human-readable (truncated) ID of the protocol, derived from the descriptor.
func (d Descriptor) HID() string {
	h := partyListToString(d.Participants)
	return fmt.Sprintf("%s-%x", d.Signature, h[:hidHashHexCharCount>>1])
}

// String returns the string representation of the protocol descriptor.
func (pd Descriptor) String() string {
	return fmt.Sprintf("{ID: %v, Type: %v, Args: %v, Aggregator: %v, Participants: %v}",
		pd.HID(), pd.Signature.Type, pd.Signature.Args, pd.Aggregator, pd.Participants)
}

// MarshalBinary returns the binary representation of the protocol descriptor.
func (pd Descriptor) MarshalBinary() (b []byte, err error) {
	return json.Marshal(pd)
}

// UnmarshalBinary unmarshals the binary representation of the protocol descriptor.
func (pd *Descriptor) UnmarshalBinary(b []byte) (err error) {
	return json.Unmarshal(b, &pd)
}

// Copy returns a copy of the Share.
func (s Share) Copy() Share {
	switch st := s.MHEShare.(type) {
	case *drlwe.PublicKeyGenShare:
		return Share{ShareMetadata: s.ShareMetadata, MHEShare: &drlwe.PublicKeyGenShare{Value: *st.Value.CopyNew()}}
	default:
		panic("not implemented") // TODO: implement on Lattigo side ?
	}
}

// MarshalBinary returns the binary representation of the share.
func (s Share) MarshalBinary() ([]byte, error) {
	return s.MHEShare.MarshalBinary()
}

// UnmarshalBinary unmarshals the binary representation of the share.
func (s Share) UnmarshalBinary(data []byte) error {
	return s.MHEShare.UnmarshalBinary(data)
}

// GetParticipants returns a set of protocol participants, given the online nodes and the threshold.
// This function handle the case of the DEC protocol, where the target must be considered a participant.
// It returns an error if there are not enough online nodes.
func GetParticipants(sig Signature, onlineNodes utils.Set[helium.NodeID], threshold int) ([]helium.NodeID, error) {
	if len(onlineNodes) < threshold {
		return nil, fmt.Errorf("not enough online node")
	}

	available := onlineNodes.Copy()
	selected := utils.NewEmptySet[helium.NodeID]()
	needed := threshold
	if sig.Type == DEC {
		target := helium.NodeID(sig.Args["target"])
		selected.Add(target)
		available.Remove(target)
		needed--
	}
	selected.AddAll(utils.GetRandomSetOfSize(needed, available))
	return selected.Elements(), nil

}

// GetProtocolPublicRandomness intitializes a keyed PRF from the session's public seed and
// the protocol's information.
// This function ensures that the PRF is unique for each protocol execution.
func GetProtocolPublicRandomness(pd Descriptor, sess *session.Session) blake2b.XOF {
	xof, _ := blake2b.NewXOF(blake2b.OutputLengthUnknown, nil)
	_, err := xof.Write(sess.PublicSeed)
	if err != nil {
		panic(err)
	}
	_, err = xof.Write([]byte(pd.Signature.String()))
	if err != nil {
		panic(err)
	}
	hashPart := partyListToString(pd.Participants)
	_, err = xof.Write(hashPart[:])
	if err != nil {
		panic(err)
	}
	return xof
}

// GetProtocolPrivateRandomness intitializes a keyed PRF from the session's private seed and
// the protocol's information.
// This function ensures that the PRF is unique for each protocol execution.
func GetProtocolPrivateRandomness(pd Descriptor, sess *session.Session) blake2b.XOF {
	xof := GetProtocolPublicRandomness(pd, sess)
	_, err := xof.Write(sess.PrivateSeed)
	if err != nil {
		panic(err)
	}
	return xof
}

func partyListToString(partList []helium.NodeID) []byte {
	partListSorted := make(sort.StringSlice, len(partList))
	for i, nid := range partList {
		partListSorted[i] = string(nid)
	}
	if !sort.StringsAreSorted(partListSorted) {
		sort.Sort(partListSorted)
	}
	s := strings.Join(partListSorted, "")
	return []byte(s)
}

// AllocateOutput returns a newly allocated output for the protocol signature.
func AllocateOutput(sig Signature, params rlwe.Parameters) interface{} {
	switch sig.Type {
	case CKG:
		return rlwe.NewPublicKey(params)
	case RTG:
		return rlwe.NewGaloisKey(params)
	case RKG:
		return rlwe.NewRelinearizationKey(params)
	case DEC:
		lvl := params.MaxLevel()
		lvlStr, has := sig.Args["level"]
		if has {
			var err error
			lvl, err = strconv.Atoi(lvlStr)
			if err != nil {
				return fmt.Errorf("invalid level: %s", lvlStr)
			}
		}
		return rlwe.NewCiphertext(params, 1, lvl)
	default:
		panic("unknown protocol type")
	}
}
