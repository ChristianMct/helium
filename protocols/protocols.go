// Package protocols implements the execution of the MHE protocols of a Helium session.
//
// It builds on the multiparty package of Lattigo, which provides the cryptographic
// protocols (CKG, RTG, RKG, key switching), and adds what is needed to run them among
// the nodes of a session:
//
//   - A common interface to the MHE protocols, [Protocol], identified by a [Signature] and
//     executed by a [Descriptor] (signature, participants and aggregator). It is built on
//     an adapter that wraps each Lattigo protocol behind a single, private interface, so that
//     the rest of Helium neither depends on the specifics of the Lattigo types nor on their
//     differing share, input and output types. The protocols' randomness (CRPs, private
//     seeding) is derived from the session's seeds.
//   - A protocol [Runner], the state machine of a node in the protocols of a session. It
//     is driven by the coordination events of a [Coordinator] (e.g., the [CentralCoordinator]
//     of the helper-assisted setting) and by incoming shares, and takes care of generating
//     and sending the node's shares, aggregating them, and storing the outputs.
//   - The masking of the key-switching shares in the T-out-of-N sessions, which makes it
//     secure to retry a decryption with another set of participants, as presented in
//     "On Threshold Fully Homomorphic Encryption with Synchronized Decryptors"
//     (https://eprint.iacr.org/2026/031). See [Protocol.GenShare].
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

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/utils"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	mhe "github.com/tuneinsight/lattigo/v6/multiparty"
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
	// RKG1 is the first round of the relinearization key generation protocol.
	RKG1
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
	MHEShare lattigoShare
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

	// sess is used to derive the protocol's randomness on demand (see [GetPublicPRNG] and [GetPrivatePRNG]),
	// so that the Protocol does not hold any random stream state across calls.
	sess *helium.Session

	proto mheProtocol

	// aggregator only
	agg *shareAggregator
}

// NewProtocol creates a new protocol from the provided protocol descriptor, session and inputs.
func NewProtocol(pd Descriptor, sess *helium.Session) (*Protocol, error) {

	err := checkProtocolDescriptor(pd, sess)
	if err != nil {
		return nil, fmt.Errorf("invalid protocol descriptor: %w", err)
	}

	p := &Protocol{id: pd.ID(), hid: pd.HID(), pd: pd, self: sess.NodeID, sess: sess}

	// intialize the protocol
	p.proto, err = newMHEProtocol(pd.Signature, *sess.Params.GetRLWEParameters()) // TODO: lattigo could return rlwe.Parameters
	if err != nil {
		return nil, err
	}

	if p.IsAggregator() {
		p.agg = newShareAggregator(pd, p.proto.allocateShare(), p.proto.aggregatedShares) // TODO: could cache the shares
	}

	// protocol-type-specific initialization
	switch {
	case (p.pd.Type == RKG1 || p.pd.Type == RKG) && p.IsParticipant():
		p.proto.(*rkgProtocol).ephSk, err = sess.GetRLKEphemeralSecretKey()
		if err != nil {
			return nil, err
		}
	}

	return p, nil
}

// AllocateShare returns a newly allocated share for the protocol.
func (p *Protocol) AllocateShare() Share {
	return p.proto.allocateShare()
}

// ReadCRP reads the common random polynomial for this protocol. Returns an error
// if called for a protocol that does not use CRP.
func (p *Protocol) ReadCRP() (CRP, error) {
	switch p.pd.Type {
	case CKG, RTG, RKG, RKG1:
		return p.proto.readCRP(GetPublicPRNG(p.pd, p.sess))
	}
	return nil, fmt.Errorf("protocol does not use CRP")
}

// GenShare is called by the session nodes to generate their share in the protocol,
// storing the result in the provided shareOut. The method returns an error if the node should
// not generate a share in the protocol. The share is computed by calling the `GenShare`
// method of Lattigo.
//
// # T-out-of-N Threshold Decryption
//
// Helium attempts to retry DEC protocols under different participant sets in the T-out-of-N
// threshold setting. However, the proposed techniques based on ct re-randomization was
// shown to be insecure (see https://eprint.iacr.org/2026/031, Section 4). The same work
// provides a secure technique based on share masking (see https://eprint.iacr.org/2026/031,
// Section 5): each node i in S adds to its share in the DEC protocol the mask
//
//	r_i = sum_{j in S} F(k_{i,j}, (S, ct)) - F(k_{j,i}, (S, ct))
//
// where F is a PRF with range R_q and the k_{i,j} are the nodes' mask keys (see
// [helium.MaskKeyPair]). The masks of the nodes in S sum to zero, and a share is pseudorandom
// until all the nodes in S have released theirs for the same (S, ct).
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

	privPRNG, err := GetPrivatePRNG(p.pd, p.sess)
	if err != nil {
		return fmt.Errorf("cannot get private PRNG: %w", err)
	}

	var ctDigest []byte
	_, isKeySwitch := in.(*KeySwitchInput)

	// for key-switches, the private PRNG must depend on the target ciphertext
	if isKeySwitch {
		ctDigest, err = keySwitchInputDigest(in)
		if err != nil {
			return err
		}
		if _, err := privPRNG.Write(ctDigest); err != nil {
			panic(err)
		}
	}

	prngs := rlwe.PRNGs{PrivatePRNG: privPRNG}
	if err := p.proto.genShare(prngs, sk, in, *shareOut); err != nil {
		return err
	}

	if p.isMasked() { // implies isKeySwitch, so ctDigest is set
		cksShare, ok := shareOut.MHEShare.(*mhe.KeySwitchShare)
		if !ok {
			return fmt.Errorf("bad share type: %T instead of %T", shareOut.MHEShare, cksShare)
		}

		if err := p.addKeySwitchMask(ctDigest, cksShare.Level(), cksShare.Value); err != nil {
			return fmt.Errorf("cannot mask share: %w", err)
		}
	}
	return nil
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
					err = fmt.Errorf("incoming channel closed before completing aggregation, still expecting: %s", p.agg.missing())
					continue
				}
				done, err = p.agg.put(share)
				//p.Logf("new share from %s, done=%v, err=%v", share.From, done, err)
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
			aggOut.Share = p.agg.getAggregatedShare()
			//p.Logf("aggregation done")
		} else {
			aggOut.Error = err
			p.Logf("aggregation error: %s", err)
		}
		aggOutChan <- aggOut
		close(aggOutChan)
	}()

	//p.Logf("[%s] aggregating shares", p.HID())

	return aggOutChan
}

// PutShare aggregates a single share into the protocol's aggregate. It is the synchronous
// counterpart of Aggregate, meant for callers that drive the aggregation as a state machine.
// It returns whether the aggregation is complete after this share, and an error if the share
// cannot be aggregated (in which case the aggregation state is unchanged).
// The method panics if called by a non-aggregator node.
func (p *Protocol) PutShare(share Share) (complete bool, err error) {
	if !p.IsAggregator() {
		panic(fmt.Errorf("node is not the aggregator"))
	}
	return p.agg.put(share)
}

// AggregatedShare returns the current aggregated share, with its metadata set.
// The share is complete only if PutShare has returned complete=true.
// The method panics if called by a non-aggregator node.
func (p *Protocol) AggregatedShare() Share {
	if !p.IsAggregator() {
		panic(fmt.Errorf("node is not the aggregator"))
	}
	agg := p.agg.getAggregatedShare()
	agg.ProtocolID = p.id
	agg.ProtocolType = p.pd.Type
	return agg
}

// Missing returns the set of participants whose share has not been aggregated yet.
// The method panics if called by a non-aggregator node.
func (p *Protocol) Missing() utils.Set[helium.NodeID] {
	if !p.IsAggregator() {
		panic(fmt.Errorf("node is not the aggregator"))
	}
	return p.agg.missing()
}

// Output computes the output of the protocol from the input and aggregation output, storing the result in out.
// Out must be a pointer to the type of the protocol's output, see AllocateOutput.
func (p *Protocol) Output(in Input, agg AggregationOutput, out interface{}) error {
	if agg.Error != nil {
		return fmt.Errorf("error at aggregation: %w", agg.Error)
	}

	if err := p.proto.finalize(in, agg.Share, out); err != nil {
		return fmt.Errorf("error at output: %w", err)
	}

	//  For T-out-of-N decryptions, adds the mask of the target (which has provided no share for aggregation).
	if p.isMasked() && p.isSessionReceiver() {
		outCt, ok := out.(*rlwe.Ciphertext)
		if !ok {
			return fmt.Errorf("bad receiver type: %T instead of %T", out, outCt)
		}

		ctDigest, err := keySwitchInputDigest(in) // TODO: recomputes the digest and mask if the same Protocol ran GenShare, could be cached.
		if err != nil {
			return err
		}

		if err := p.addKeySwitchMask(ctDigest, in.(*KeySwitchInput).InpuCt.Level(), outCt.Value[0]); err != nil {
			return fmt.Errorf("cannot unmask output: %w", err)
		}
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

// isSessionReceiver returns whether the node is the target of the DEC protocol and one of
// its participants. Such a node does not provide a share (hence, no mask) to the aggregator.
func (p *Protocol) isSessionReceiver() bool {
	return p.pd.Type == DEC && p.pd.Args["target"] == string(p.self) && p.IsParticipant()
}

func checkProtocolDescriptor(pd Descriptor, sess *helium.Session) error {

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
func (t Type) Share() lattigoShare {
	switch t {
	case SKG:
		return &mhe.ShamirSecretShare{}
	case CKG:
		return &mhe.PublicKeyGenShare{}
	case RKG1, RKG:
		return &mhe.RelinearizationKeyGenShare{}
	case RTG:
		return &mhe.GaloisKeyGenShare{}
	case CKS, DEC:
		return &mhe.KeySwitchShare{}
	case PCKS:
		return &mhe.PublicKeySwitchShare{}
	default:
		return nil
	}
}

// IsSetup returns whether the protocol type is a key generation protocol.
func (t Type) IsSetup() bool {
	switch t {
	case CKG, RTG, RKG, RKG1:
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
func (s Signature) String() string {
	args := make(sort.StringSlice, 0, len(s.Args))
	for argname, argval := range s.Args {
		args = append(args, fmt.Sprintf("%s=%s", argname, argval))
	}
	sort.Sort(args)
	return fmt.Sprintf("%s(%s)", s.Type, strings.Join(args, ","))
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
func (pd Descriptor) ID() ID {
	h := blake2b.Sum256(partyListToString(pd.Participants))
	return ID(fmt.Sprintf("%s-%x", pd.Signature, h[:]))
}

// HID returns the human-readable (truncated) ID of the protocol, derived from the descriptor.
func (pd Descriptor) HID() string {
	h := blake2b.Sum256(partyListToString(pd.Participants))
	return fmt.Sprintf("%s-%x", pd.Signature, h[:hidHashHexCharCount>>1])
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
	case *mhe.PublicKeyGenShare:
		return Share{ShareMetadata: s.ShareMetadata, MHEShare: &mhe.PublicKeyGenShare{Value: *st.Value.CopyNew()}}
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

// GetPublicPRNG intitializes a keyed PRF from the session's public seed and
// the protocol's information.
// This function ensures that the PRF is unique for each protocol execution.
// Each call returns a new, independent stream in its initial state.
func GetPublicPRNG(pd Descriptor, sess *helium.Session) blake2b.XOF {
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

// GetPrivatePRNG intitializes a keyed PRF from the session's private seed and
// the protocol's information.
// This function ensures that the PRF is unique for each protocol execution.
// Each call returns a new, independent stream in its initial state.
// It returns an error if the session has no private seed, as the resulting
// stream would otherwise be equal to the public one.
func GetPrivatePRNG(pd Descriptor, sess *helium.Session) (blake2b.XOF, error) {
	if len(sess.PrivateSeed) == 0 {
		return nil, fmt.Errorf("session has no private seed")
	}
	xof := GetPublicPRNG(pd, sess)
	_, err := xof.Write(sess.PrivateSeed)
	if err != nil {
		panic(err)
	}
	return xof, nil
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
