package protocols

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/ldsec/helium/pkg"
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
	Round []Share
	Error error
}

type Instance interface {
	ID() pkg.ProtocolID
	Desc() Descriptor

	Aggregate(ctx context.Context, env Transport) chan AggregationOutput
	Output(AggregationOutput) chan Output
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
		return &drlwe.CKGShare{}
	case RKG_1, RKG_2:
		return &drlwe.RKGShare{}
	case RTG:
		return &drlwe.RTGShare{}
	case CKS, DEC:
		return &drlwe.CKSShare{}
	case PCKS:
		return &drlwe.PCKSShare{}
	case PK:
		return &drlwe.CKGShare{}
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

// ToObjectStore returns a string used to index the output of the protocol into the ObjectStore.
func (t Signature) ToObjectStore() string {
	if t.Args == nil {
		t.Args = map[string]string{} // prevents different rep for nil and empty
	}
	s := fmt.Sprint(t.Type)
	if len(t.Args) > 0 {
		s += fmt.Sprint(t.Args)
	}

	return s
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
	sk   *rlwe.SecretKey

	shareProviders utils.Set[pkg.NodeID]
}

type cpkProtocol struct {
	*protocol
	proto LattigoKeygenProtocol
	agg   shareAggregator
	crs   drlwe.CRS
	crp   CRP
	//prevRoundShare *Share
}

// type rkgProtocol struct {
// 	*protocol
// 	proto      LattigoKeygenProtocol
// 	agg1, agg2 shareAggregator
// 	crs        drlwe.CRS
// 	crp        CRP

// 	// state
// 	ephSk      *rlwe.SecretKey
// 	aggShareR1 *Share
// }

func NewProtocol(pd Descriptor, sess *pkg.Session) (Instance, error) {
	switch pd.Signature.Type {
	// case SKG:
	// 	p := newProtocol(pd, sk, id)
	// 	return &skgProtocol{protocol: p, T: sess.T, proto: SKGProtocol{Thresholdizer: *drlwe.NewThresholdizer(*sess.Params)}}, nil
	case CKG, RTG, RKG_1, RKG_2, PK:
		return NewKeygenProtocol(pd, sess)
	case CKS, DEC, PCKS:
		return NewKeyswitchProtocol(pd, sess, nil)
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
	if p.shareProviders.Contains(p.self) {
		p.sk, err = sess.GetSecretKeyForGroup(pd.Participants)
	}
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
		p.proto, err = NewCKGProtocol(*sess.Params, pd.Signature.Args)
		inst = p
	case RTG:
		p = new(cpkProtocol)
		p.protocol = protocol
		p.crs = GetCRSForProtocol(pd, sess)
		p.proto, err = NewRTGProtocol(*sess.Params, pd.Signature.Args)
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
		p.proto, err = NewRKGProtocol(*sess.Params, ephSk, 1, pd.Signature.Args)
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
		p.proto, err = NewRKGProtocol(*sess.Params, ephSk, 2, pd.Signature.Args)
		inst = p
	// case PK:
	// 	p := new(pkProtocol)
	// 	p.protocol = protocol
	// 	p.crs = sess.GetCRSForProtocol(pd.ID)
	// 	p.proto, err = NewCKGProtocol(*sess.Params, pd.Args)
	// 	inst = p
	default:
		err = fmt.Errorf("unknown protocol type: %s", pd.Signature.Type)
	}
	if err != nil {
		inst = nil
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

// run runs the cpkProtocol allowing participants to provide shares and aggregators to aggregate such shares.
func (p *cpkProtocol) run(ctx context.Context, env Transport) AggregationOutput {
	p.Logf("started running with %v", p.Descriptor)

	if p.Signature.Type == RKG_2 {
		select {
		case s := <-env.IncomingShares():
			p.crp = s.MHEShare // for the second round of RKG, the CRP is the round 1 agg. share.
		case <-ctx.Done():
			err := fmt.Errorf("%s | timeout while waiting for round 1 aggregated share for protocol %s", p.self, p.ID())
			return AggregationOutput{Error: err}
		}
		log.Printf("%s | got round 1 aggregated share\n", p.self)
	} else {
		var err error
		p.crp, err = p.proto.ReadCRP(p.crs)
		if err != nil {
			panic(err)
		}
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
		return AggregationOutput{Round: []Share{share}}
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
		var err error
		p.crp, err = p.proto.ReadCRP(p.crs)
		if err != nil {
			panic(err)
		}
	}
	res, err := p.proto.Finalize(p.crp, agg.Round...)
	if err != nil {
		out <- Output{Error: fmt.Errorf("error at finalization: %w", err)}
		return out
	}
	p.Logf("finalized protocol")
	out <- Output{Result: res}
	return out
}

// func (p *rkgProtocol) Aggregate(ctx context.Context, env Transport) chan AggregationOutput {
// 	output := make(chan AggregationOutput)
// 	go func() {
// 		switch p.Signature.Type {
// 		case RKG_1:
// 			output <- p.runRoundOne(ctx, env)
// 		case RKG_2:
// 			output <- p.runRoundTwo(ctx, env)
// 		default:
// 			panic("bad protocol type")
// 		}

// 	}()
// 	return output
// }

// // runRoundOne runs the rkgProtocol allowing participants to provide shares and aggregators to aggregate such shares.
// func (p *rkgProtocol) runRoundOne(ctx context.Context, env Transport) AggregationOutput {

// 	p.Logf("started running with %v", p.Descriptor)

// 	var err error
// 	p.crp, err = p.proto.ReadCRP(p.crs)
// 	if err != nil {
// 		panic(err)
// 	}

// 	var shareR1, shareR2 Share
// 	if p.IsAggregator() || p.shareProviders.Contains(p.self) {
// 		p.ephSk, shareR1, shareR2 = p.proto.AllocateShare()
// 		shareR1.AggregateFor = utils.NewEmptySet[pkg.NodeID]()
// 		shareR2.AggregateFor = utils.NewEmptySet[pkg.NodeID]()
// 	}

// 	if p.shareProviders.Contains(p.self) {
// 		errGen := p.proto.GenShareRoundOne(p.sk, p.crp, p.ephSk, shareR1)
// 		if errGen != nil {
// 			panic(errGen)
// 		}
// 		shareR1.ProtocolID = p.ID()
// 		shareR1.Type = p.Signature.Type
// 		shareR1.From = p.self
// 		shareR1.To = []pkg.NodeID{p.Desc().Aggregator}
// 		shareR1.AggregateFor = utils.NewSingletonSet(p.self)
// 		shareR1.Round = 1
// 	}

// 	if p.IsAggregator() {
// 		p.agg1 = *newShareAggregator(p.shareProviders, shareR1, p.proto.AggregatedShares)

// 		errAggr := p.aggregateShares(ctx, p.agg1, env)
// 		if errAggr != nil {
// 			p.Logf("failed: %s", errAggr)
// 			return AggregationOutput{Error: errAggr}
// 		}

// 		p.Logf("completed round 1 aggregation")

// 		shareR1 = p.agg1.GetAggregatedShare()
// 		shareR1.ProtocolID = p.ID()
// 		shareR1.Type = p.Signature.Type
// 		shareR1.From = p.self
// 		shareR1.To = p.Participants
// 		shareR1.AggregateFor = p.shareProviders.Copy()
// 		p.Signature.Type = RKG_2
// 		p.aggShareR1 = &shareR1
// 		return AggregationOutput{Round: []Share{shareR1}}
// 	}

// 	p.Signature.Type = RKG_2

// 	if p.shareProviders.Contains(p.self) {
// 		env.OutgoingShares() <- shareR1 // must be done after aggregator reads from incoming chan
// 	}

// 	return AggregationOutput{}
// }

// func (p *rkgProtocol) runRoundTwo(ctx context.Context, env Transport) AggregationOutput {

// 	p.Logf("started running with %v", p.Descriptor)

// 	var err error
// 	if p.aggShareR1 == nil && p.shareProviders.Contains(p.self) {
// 		select {
// 		case s := <-env.IncomingShares():
// 			p.aggShareR1 = &s
// 		case <-ctx.Done():
// 			err = fmt.Errorf("%s | timeout while waiting for round 1 aggregated share for protocol %s", p.self, p.ID())
// 			return AggregationOutput{Error: err}
// 		}
// 		log.Printf("%s | got round 1 aggregated share\n", p.self)
// 	}

// 	shareR2 := p.proto.AllocateShare()
// 	shareR2.AggregateFor = utils.NewEmptySet[pkg.NodeID]()
// 	if p.shareProviders.Contains(p.self) {

// 		errGen := p.proto.GenShare(p.sk, *p.aggShareR1, shareR2)
// 		if errGen != nil {
// 			panic(errGen)
// 		}
// 		shareR2.ProtocolID = p.ID()
// 		shareR2.Type = p.Signature.Type
// 		shareR2.From = p.self
// 		shareR2.To = []pkg.NodeID{p.Desc().Aggregator}
// 		shareR2.AggregateFor = utils.NewSingletonSet(p.self)
// 		shareR2.Round = 2
// 	}

// 	if p.IsAggregator() {
// 		p.agg2 = *newShareAggregator(p.shareProviders, shareR2, p.proto.AggregatedShares)
// 		errAggr := p.aggregateShares(ctx, p.agg2, env)
// 		if errAggr != nil {
// 			p.Logf("failed: %s", errAggr)
// 			return AggregationOutput{Error: errAggr}
// 		}

// 		p.Logf("completed round 2 aggregation")

// 		shareR2 = p.agg2.GetAggregatedShare()
// 		shareR2.ProtocolID = p.ID()
// 		shareR2.Type = p.Signature.Type
// 		shareR2.From = p.self
// 		shareR2.AggregateFor = p.shareProviders.Copy()
// 		p.Logf("completed aggregation")
// 		return AggregationOutput{Round: []Share{shareR2}}
// 	}

// 	if p.shareProviders.Contains(p.self) {
// 		env.OutgoingShares() <- shareR2 // must be done after aggregator reads from incoming chan
// 	}

// 	return AggregationOutput{}
// }

// func (p rkgProtocol) Output(agg AggregationOutput) chan Output { // TODO Copy-past from pkProtocol
// 	out := make(chan Output, 1)
// 	if agg.Error != nil {
// 		out <- Output{Error: fmt.Errorf("error at aggregation: %w", agg.Error)}
// 		return out
// 	}
// 	if p.crp == nil {
// 		var err error
// 		p.crp, err = p.proto.ReadCRP(p.crs)
// 		if err != nil {
// 			panic(err)
// 		}
// 	}
// 	res, err := p.proto.Finalize(p.crp, agg.Round...)
// 	if err != nil {
// 		out <- Output{Error: fmt.Errorf("error at finalization: %w", err)}
// 		return out
// 	}
// 	p.Logf("finalized protocol")
// 	out <- Output{Result: res}
// 	return out
// }

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

// func (p *rkgProtocol) AllocateShare() Share {
// 	s := p.proto.AllocateShare()
// 	return s
// }

func (p protocol) aggregateShares(ctx context.Context, aggregator shareAggregator, env Transport) error {
	for {
		select {
		case share := <-env.IncomingShares():
			p.Logf("new share from %s", share.From)
			done, err := aggregator.PutShare(share)
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

func (p *protocol) IsAggregator() bool {
	return p.Descriptor.Aggregator == p.self || p.Descriptor.Signature.Type == SKG
}

func (p protocol) Logf(msg string, v ...any) {
	log.Printf("%s | [%s] %s\n", p.self, p.HID(), fmt.Sprintf(msg, v...))
}

func (s Share) Copy() Share {
	switch st := s.MHEShare.(type) {
	case *drlwe.CKGShare:
		return Share{ShareDescriptor: s.ShareDescriptor, MHEShare: &drlwe.CKGShare{Value: st.Value.CopyNew()}}
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
