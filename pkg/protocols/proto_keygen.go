package protocols

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"

	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v4/drlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"golang.org/x/crypto/blake2b"
)

type ShareDescriptor struct {
	pkg.ProtocolID
	Type         Type
	Round        uint64
	From         pkg.NodeID
	To           []pkg.NodeID
	AggregateFor utils.Set[pkg.NodeID]
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
	Share Share
	Error error
}

type Instance interface {
	ID() pkg.ProtocolID
	Desc() Descriptor

	ReadCRP() (CRP, error)
	Init(CRP) error
	Aggregate(ctx context.Context, env Transport) chan AggregationOutput
	Output(agg AggregationOutput) chan Output

	HasShareFrom(pkg.NodeID) bool
}

type KeySwitchInstance interface {
	Instance
	Input(ct *rlwe.Ciphertext)
}

type Type uint

const (
	Unknown Type = iota
	SKG
	CKG
	RKG_1
	RKG_2
	RTG
	CKS
	DEC
	PCKS
	PK
)

var typeToString = []string{"Unknown", "SKG", "CKG", "RKG_1", "RKG_2", "RTG", "CKS", "DEC", "PCKS", "PK"}

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
	case RKG_1, RKG_2:
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
	L sync.RWMutex

	self pkg.NodeID
	sk   *rlwe.SecretKey

	shareProviders utils.Set[pkg.NodeID]
	agg            shareAggregator
}

type cpkProtocol struct {
	*protocol
	proto LattigoKeygenProtocol
	crs   drlwe.CRS
	crp   CRP
}

func NewProtocol(pd Descriptor, sess *pkg.Session) (Instance, error) {
	switch pd.Signature.Type {
	// case SKG:
	// 	p := newProtocol(pd, sk, id)
	// 	return &skgProtocol{protocol: p, T: sess.T, proto: SKGProtocol{Thresholdizer: *drlwe.NewThresholdizer(*sess.Params)}}, nil
	case CKG, RTG, RKG_1, RKG_2, PK:
		return NewKeygenProtocol(pd, sess)
	case CKS, DEC, PCKS:
		return NewKeyswitchProtocol(pd, sess)
	default:
		return nil, fmt.Errorf("unknown protocol type: %s", pd.Signature.Type)
	}
}

func newProtocol(pd Descriptor, sess *pkg.Session) (p *protocol, err error) {
	p = new(protocol)
	p.self = sess.NodeID
	p.Descriptor = pd
	p.ProtocolID = pd.ID()
	p.shareProviders = utils.NewSet(pd.Participants)
	return p, err
}

func NewKeygenProtocol(pd Descriptor, sess *pkg.Session) (Instance, error) {
	var inst Instance
	protocol, err := newProtocol(pd, sess)
	if err != nil {
		return nil, err
	}
	var p *cpkProtocol
	switch pd.Signature.Type {
	case CKG:
		p = new(cpkProtocol)
		p.protocol = protocol
		p.crs = GetCRSForProtocol(pd, sess)
		p.proto, err = NewCKGProtocol(*&sess.Params.Parameters, pd.Signature.Args)
		inst = p
	case RTG:
		p = new(cpkProtocol)
		p.protocol = protocol
		p.crs = GetCRSForProtocol(pd, sess)
		p.proto, err = NewRTGProtocol(*&sess.Params.Parameters, pd.Signature.Args)
		inst = p
	case RKG_1:
		p := new(cpkProtocol)
		p.protocol = protocol
		p.crs = GetCRSForProtocol(pd, sess)
		var ephSk *rlwe.SecretKey
		if utils.NewSet(sess.Nodes).Contains(sess.NodeID) {
			ephSk, err = sess.GetRLKEphemeralSecretKey()
			if err != nil {
				return nil, err
			}
		}
		p.proto, err = NewRKGProtocol(*&sess.Params.Parameters, ephSk, 1, pd.Signature.Args)
		inst = p
	case RKG_2:
		p := new(cpkProtocol)
		p.protocol = protocol
		p.crs = GetCRSForProtocol(pd, sess)
		var ephSk *rlwe.SecretKey
		if utils.NewSet(sess.Nodes).Contains(sess.NodeID) {
			ephSk, err = sess.GetRLKEphemeralSecretKey()
			if err != nil {
				return nil, err
			}
		}
		p.proto, err = NewRKGProtocol(*&sess.Params.Parameters, ephSk, 2, pd.Signature.Args)
		inst = p
	case PK:
		p := new(pkProtocol)
		p.protocol = protocol
		p.crs = GetCRSForProtocol(pd, sess)
		p.proto, err = NewCKGProtocol(*&sess.Params.Parameters, pd.Signature.Args)
		inst = p
	default:
		err = fmt.Errorf("unknown protocol type: %s", pd.Signature.Type)
	}
	if err != nil {
		inst = nil
	}

	if protocol.shareProviders.Contains(protocol.self) {
		switch pd.Signature.Type {
		case CKG, RKG_1, RKG_2, RTG:
			protocol.sk, err = sess.GetSecretKeyForGroup(pd.Participants)
		case PK:
			protocol.sk, err = sess.GetSecretKey()
		}
	}

	return inst, err
}

func GetCRSForProtocol(pd Descriptor, sess *pkg.Session) drlwe.CRS {
	pid := pd.ID()
	xof, _ := blake2b.NewXOF(blake2b.OutputLengthUnknown, nil)
	_, err := xof.Write(sess.PublicSeed)
	if err != nil {
		panic(err)
	}
	_, err = xof.Write([]byte(pid))
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

func (p *cpkProtocol) Init(crp CRP) (err error) {
	p.crp = crp
	return nil
}

func (p *cpkProtocol) ReadCRP() (CRP, error) {
	return p.proto.ReadCRP(p.crs)
}

// run runs the cpkProtocol allowing participants to provide shares and aggregators to aggregate such shares.
func (p *cpkProtocol) run(ctx context.Context, env Transport) AggregationOutput {
	p.Logf("started running with participants %v", p.Descriptor.Participants)

	if p.crp == nil {
		panic(fmt.Errorf("Aggregate method called before Init at node %s", p.self))
	}

	var share Share
	if p.IsAggregator() || p.shareProviders.Contains(p.self) {
		share = p.proto.AllocateShare()
		share.ProtocolID = p.ID()
		share.Type = p.Signature.Type
		share.From = p.self
		share.AggregateFor = utils.NewEmptySet[pkg.NodeID]()
		share.Round = 1
	}

	if p.shareProviders.Contains(p.self) {
		errGen := p.proto.GenShare(p.sk, p.crp, share)
		if errGen != nil {
			panic(errGen)
		}
		share.To = []pkg.NodeID{p.Desc().Aggregator}
		share.AggregateFor.Add(p.self)
	}

	if p.IsAggregator() {
		p.agg = *newShareAggregator(p.shareProviders, share, p.proto.AggregatedShares)

		errAggr := p.aggregateShares(ctx, p.agg, env)
		if errAggr != nil {
			p.Logf("failed: %s", errAggr)
			return AggregationOutput{Error: errAggr}
		}
		share.AggregateFor = p.shareProviders.Copy()
		p.Logf("completed aggregating")
		return AggregationOutput{Share: share}
	}
	if p.shareProviders.Contains(p.self) {
		env.OutgoingShares() <- share
		p.Logf("completed participanting")
	}
	p.Logf("completed running")
	return AggregationOutput{}
}

func (p *cpkProtocol) Aggregate(ctx context.Context, env Transport) chan AggregationOutput {
	output := make(chan AggregationOutput)
	go func() {
		output <- p.run(ctx, env)
	}()
	return output
}

func (p *cpkProtocol) Output(agg AggregationOutput) chan Output {
	out := make(chan Output, 1)
	if agg.Error != nil {
		out <- Output{Error: fmt.Errorf("error at aggregation: %w", agg.Error)}
		return out
	}
	if p.crp == nil {
		// var err error
		// p.crp, err = p.proto.ReadCRP(p.crs)
		// if err != nil {
		// 	panic(err)
		// }
		panic("Output method called before Init")
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

func (p protocol) aggregateShares(ctx context.Context, aggregator shareAggregator, env Transport) error {
	for {
		select {
		case share := <-env.IncomingShares():
			p.L.Lock()
			done, err := aggregator.PutShare(share)
			p.L.Unlock()
			//p.Logf("new share from %s, done=%v, err=%v", share.From, done, err)
			if err != nil {
				return err
			}
			if done {
				return nil
			}
		case <-ctx.Done():
			return fmt.Errorf("%s | timeout while aggregating shares for protocol %s, missing: %v", p.self, p.ID(), aggregator.Missing())
		}
	}
}

func (p *protocol) HasShareFrom(nid pkg.NodeID) bool {
	p.L.RLock()
	defer p.L.RUnlock()
	return !p.agg.Missing().Contains(nid)
}

func (p *protocol) IsAggregator() bool {
	return p.Descriptor.Aggregator == p.self || p.Descriptor.Signature.Type == SKG
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
