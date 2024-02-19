package protocols

import (
	"context"
	"fmt"
	"log"
	"slices"
	"sort"
	"strings"

	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v4/drlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"golang.org/x/crypto/blake2b"
)

type ShareDescriptor struct {
	pkg.ProtocolID
	Type
	From utils.Set[pkg.NodeID]
}

type Share struct {
	ShareDescriptor
	MHEShare LattigoShare
}

type Input interface{}

type Output struct {
	Result interface{}
	Error  error
}

type OutputKey interface{}

type CRP interface{}

type AggregationOutput struct {
	Share      Share
	Descriptor Descriptor
	Error      error
}

type Instance interface {
	ID() pkg.ProtocolID
	Desc() Descriptor

	AllocateShare() Share
	GenShare(*Share) error
	Aggregate(ctx context.Context, incoming <-chan Share) (chan AggregationOutput, error)
	HasShareFrom(pkg.NodeID) bool
	Output(agg AggregationOutput) chan Output
}

type Type uint

const (
	Unknown Type = iota
	SKG
	CKG
	RKG_1
	RKG
	RTG
	CKS
	DEC
	PCKS
	PK
)

var typeToString = []string{"Unknown", "SKG", "CKG", "RKG_1", "RKG", "RTG", "CKS", "DEC", "PCKS", "PK"}

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
	case PK:
		return &drlwe.PublicKeyGenShare{}
	default:
		return nil
	}
}

type Signature struct {
	Type Type
	Args map[string]string
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

type protocol struct {
	pkg.ProtocolID
	Descriptor

	self pkg.NodeID

	sk *rlwe.SecretKey

	pubrand, privrand blake2b.XOF

	agg *shareAggregator
}

func newProtocol(pd Descriptor, sess *pkg.Session) (*protocol, error) {

	if len(pd.Participants) < sess.T {
		return nil, fmt.Errorf("invalid protocol descriptor: not enough participant to execute protocol: %d < %d", len(pd.Participants), sess.T)
	}

	for _, p := range pd.Participants {
		if !sess.Contains(p) {
			return nil, fmt.Errorf("participant %s not in session", p)
		}
	}

	p := &protocol{ProtocolID: pd.ID(), Descriptor: pd, self: sess.NodeID}
	return p, nil
}

type cpkProtocol struct {
	protocol
	proto LattigoKeygenProtocol
	crp   CRP
}

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

func NewKeygenProtocol(pd Descriptor, sess *pkg.Session, inputs ...Input) (Instance, error) {

	prot, err := newProtocol(pd, sess)
	if err != nil {
		return nil, err
	}

	p := &cpkProtocol{
		protocol: *prot,
	}

	switch pd.Signature.Type {
	case CKG:
		p.proto, err = NewCKGProtocol(*&sess.Params.Parameters, pd.Signature.Args)
	case RTG:
		p.proto, err = NewRTGProtocol(*&sess.Params.Parameters, pd.Signature.Args)
	case RKG_1:
		var ephSk *rlwe.SecretKey
		if p.IsParticipant() {
			ephSk, err = sess.GetRLKEphemeralSecretKey()
			if err != nil {
				return nil, err
			}
		}
		p.proto, err = NewRKGProtocol(*&sess.Params.Parameters, ephSk, 1, pd.Signature.Args)
	case RKG:
		var ephSk *rlwe.SecretKey
		if p.IsParticipant() {
			ephSk, err = sess.GetRLKEphemeralSecretKey()
			if err != nil {
				return nil, err
			}
		}

		if len(inputs) != 1 {
			return nil, fmt.Errorf("protocol signature %s requires an input", pd.Signature.Type)
		}

		rkgR1Share, isShare := inputs[0].(Share)
		if !isShare {
			return nil, fmt.Errorf("protocol signature %s requires input of type %T, got %T", pd.Signature.Type, rkgR1Share, inputs[0])
		}

		p.crp = rkgR1Share.MHEShare

		p.proto, err = NewRKGProtocol(*&sess.Params.Parameters, ephSk, 2, pd.Signature.Args)

	default:
		err = fmt.Errorf("unknown protocol type: %s", pd.Signature.Type)
	}
	if err != nil {
		return nil, err
	}

	p.pubrand = GetProtocolPublicRandomness(pd, sess)

	if p.IsParticipant() {
		p.sk, err = sess.GetSecretKeyForGroup(pd.Participants) // TODO: could cache the group keys
		if err != nil {
			return nil, err
		}
		p.privrand = GetProtocolPrivateRandomness(pd, sess)
	}

	if p.IsAggregator() {
		p.agg = newShareAggregator(pd, p.AllocateShare(), p.proto.AggregatedShares) // TODO: could cache the shares
	}

	return p, nil
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

func (p *cpkProtocol) GenShare(share *Share) error {

	if !p.IsParticipant() {
		return fmt.Errorf("node is not a participant")
	}

	if p.crp == nil {
		var err error
		p.crp, err = p.proto.ReadCRP(p.pubrand)
		if err != nil {
			return err
		}
	}

	p.Logf("[%s] generating share", p.HID())
	share.ProtocolID = p.ProtocolID
	share.From = utils.NewSingletonSet(p.self)
	share.Type = p.Signature.Type
	return p.proto.GenShare(p.sk, p.crp, *share)
}

func (p *protocol) Aggregate(ctx context.Context, incoming <-chan Share) (chan AggregationOutput, error) {

	if !p.IsAggregator() {
		return nil, fmt.Errorf("node is not the aggregator")
	}

	aggOutChan := make(chan AggregationOutput, 1)

	go func() {
		var aggOut AggregationOutput
		var err error
		var done bool
		for !done {
			select {
			case share := <-incoming:
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

		aggOut.Descriptor = p.Descriptor
		if err == nil {
			aggOut.Share = p.agg.share
			aggOut.Share.ProtocolID = p.ProtocolID
			aggOut.Share.Type = p.Signature.Type
			p.Logf("[%s] aggregation done", p.HID())
		} else {
			aggOut.Error = err
			p.Logf("[%s] aggregation error: %s", p.HID(), err)
		}
		aggOutChan <- aggOut
	}()

	p.Logf("[%s] aggregating shares", p.HID())

	return aggOutChan, nil
}

func (p *cpkProtocol) Output(agg AggregationOutput) chan Output {
	out := make(chan Output, 1)
	if agg.Error != nil {
		out <- Output{Error: fmt.Errorf("error at aggregation: %w", agg.Error)}
		return out
	}

	if p.crp == nil {
		var err error
		p.crp, err = p.proto.ReadCRP(p.pubrand)
		if err != nil {
			out <- Output{Error: fmt.Errorf("error at finalization: %w", err)}
			return out
		}
	}

	res, err := p.proto.Finalize(p.crp, agg.Share)
	if err != nil {
		out <- Output{Error: fmt.Errorf("error at finalization: %w", err)}
		return out
	}
	p.Logf("finalized protocol")
	out <- Output{Result: res}
	return out
}

func (p *protocol) ID() pkg.ProtocolID {
	return p.ProtocolID
}

func (p *protocol) Desc() Descriptor {
	return p.Descriptor
}

func (p *cpkProtocol) AllocateShare() Share {
	return p.proto.AllocateShare()
}

func (p *skgProtocol) AllocateShare() Share {
	return p.proto.AllocateShare()
}

func (p *keySwitchProtocol) AllocateShare() Share {
	return p.proto.AllocateShare()
}

func (p *protocol) HasShareFrom(nid pkg.NodeID) bool {
	return !p.agg.Missing().Contains(nid)
}

func (p *protocol) IsAggregator() bool {
	return p.Descriptor.Aggregator == p.self || p.Descriptor.Signature.Type == SKG
}

func (p *protocol) IsParticipant() bool {
	return slices.Contains(p.Participants, p.self)
}

func (p *protocol) HasRole() bool {
	return p.IsAggregator() || p.IsParticipant()
}

func (p *protocol) Logf(msg string, v ...any) {
	if !protocolLogging {
		return
	}
	log.Printf("%s | [%s] %s\n", p.self, p.HID(), fmt.Sprintf(msg, v...))
}

func (s Share) Copy() Share {
	switch st := s.MHEShare.(type) {
	case *drlwe.PublicKeyGenShare:
		return Share{ShareDescriptor: s.ShareDescriptor, MHEShare: &drlwe.PublicKeyGenShare{Value: *st.Value.CopyNew()}}
	default:
		panic("not implemented") // TODO: implement on Lattigo side ?
	}
}

func (s Share) MarshalBinary() ([]byte, error) {
	return s.MHEShare.MarshalBinary()
}

func (s Share) UnmarshalBinary(data []byte) error {
	return s.MHEShare.UnmarshalBinary(data)
}
