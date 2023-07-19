package protocols

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v4/drlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

type Descriptor struct {
	ID pkg.ProtocolID
	Signature
	Aggregator   pkg.NodeID
	Participants []pkg.NodeID
}

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

	Aggregate(ctx context.Context, session *pkg.Session, env Transport) chan AggregationOutput
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
	RKG
	RTG
	CKS
	DEC
	PCKS
	PK
)

var typeToString = []string{"Unknown", "SKG", "CKG", "RKG", "RTG", "CKS", "DEC", "PCKS", "PK"}

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
	case RKG:
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
	if t.Args == nil {
		t.Args = map[string]string{} // prevents different rep for nil and empty
	}
	s, err := json.Marshal(t) // TODO: produce non-deterministic strings when len(Args)>1
	if err != nil {
		panic(err)
	}
	return string(s)
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

	shareProviders utils.Set[pkg.NodeID]
}

type skgProtocol struct {
	*protocol
	proto SKGProtocol
}

type cpkProtocol struct {
	*protocol
	proto LattigoKeygenProtocol
	agg   shareAggregator
	crs   drlwe.CRS
	crp   CRP
}

type rkgProtocol struct {
	*protocol
	proto      *RKGProtocol
	agg1, agg2 shareAggregator
	crs        drlwe.CRS
	crp        CRP
}

// pkProtocol is the protocol used to share public keys among parties.
type pkProtocol struct {
	*protocol
	proto LattigoKeygenProtocol
	agg   shareAggregator
	crs   drlwe.CRS
	crp   CRP
}

func NewProtocol(pd Descriptor, sess *pkg.Session, id pkg.ProtocolID) (Instance, error) {
	switch pd.Type {
	case SKG:
		p := newProtocol(pd, sess, id)
		return &skgProtocol{protocol: p, proto: SKGProtocol{Thresholdizer: *drlwe.NewThresholdizer(*sess.Params)}}, nil
	case CKG, RTG, RKG, PK:
		return NewKeygenProtocol(pd, sess, id)
	case CKS, DEC, PCKS:
		return NewKeyswitchProtocol(pd, sess, id)
	default:
		return nil, fmt.Errorf("unknown protocol type: %s", pd.Type)
	}
}

func newProtocol(pd Descriptor, sess *pkg.Session, id pkg.ProtocolID) *protocol {
	p := new(protocol)
	p.self = sess.NodeID
	p.Descriptor = pd
	p.ProtocolID = id
	p.shareProviders = utils.NewSet(pd.Participants)
	return p
}

func NewKeygenProtocol(pd Descriptor, sess *pkg.Session, id pkg.ProtocolID) (Instance, error) {
	var err error
	var inst Instance
	protocol := newProtocol(pd, sess, id)
	var p *cpkProtocol
	switch pd.Type {
	case CKG:
		p = new(cpkProtocol)
		p.protocol = protocol
		p.crs = sess.GetCRSForProtocol(pd.ID)
		p.proto, err = NewCKGProtocol(*sess.Params, pd.Args)
		inst = p
	case RTG:
		p = new(cpkProtocol)
		p.protocol = protocol
		p.crs = sess.GetCRSForProtocol(pd.ID)
		p.proto, err = NewRTGProtocol(*sess.Params, pd.Args)
		inst = p
	case RKG:
		p := new(rkgProtocol)
		p.protocol = protocol
		p.crp = sess.GetCRSForProtocol(pd.ID)
		p.proto, err = NewRKGProtocol(*sess.Params, pd.Args)
		inst = p
	case PK:
		p := new(pkProtocol)
		p.protocol = protocol
		p.crs = sess.GetCRSForProtocol(pd.ID)
		p.proto, err = NewCKGProtocol(*sess.Params, pd.Args)
		inst = p
	default:
		err = fmt.Errorf("unknown protocol type: %s", pd.Type)
	}
	if err != nil {
		inst = nil
	}
	return inst, err
}

// run runs the cpkProtocol allowing participants to provide shares and aggregators to aggregate such shares.
func (p *cpkProtocol) run(ctx context.Context, session *pkg.Session, env Transport) AggregationOutput {
	log.Printf("%s | [%s] started running with %v\n", p.self, p.ID(), p.Descriptor)

	var err error
	p.crp, err = p.proto.ReadCRP(p.crs)
	if err != nil {
		panic(err)
	}

	var share Share
	if p.IsAggregator() || p.shareProviders.Contains(p.self) {
		share = p.proto.AllocateShare()
		share.ProtocolID = p.ID()
		share.Type = p.Type
		share.From = p.self
		share.AggregateFor = utils.NewEmptySet[pkg.NodeID]()
		share.Round = 1
	}

	if p.shareProviders.Contains(p.self) {
		sk, errSk := session.SecretKeyForGroup(p.shareProviders.Elements())
		if errSk != nil {
			log.Printf("%s | error in getting sk: %s\n", p.self, errSk)
			return AggregationOutput{Error: errSk}
		}
		errGen := p.proto.GenShare(sk, p.crp, share)
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
			log.Printf("%s | [%s] failed: %s\n", p.self, p.ID(), errAggr)
			return AggregationOutput{Error: errAggr}
		}
		share.AggregateFor = p.shareProviders.Copy()
		log.Printf("%s | [%s] completed aggregating\n", p.self, p.ID())
		return AggregationOutput{Round: []Share{share}}
	}
	if p.shareProviders.Contains(p.self) {
		env.OutgoingShares() <- share
		log.Printf("%s | [%s] completed participanting\n", p.self, p.ID())
	}
	log.Printf("%s | [%s] completed running\n", p.self, p.ID())
	return AggregationOutput{}
}

func (p *cpkProtocol) Aggregate(ctx context.Context, session *pkg.Session, env Transport) chan AggregationOutput {
	output := make(chan AggregationOutput)
	go func() {
		output <- p.run(ctx, session, env)
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
	log.Printf("%s | [%s] finalized protocol\n", p.self, p.ID())
	out <- Output{Result: res}
	return out
}

// run runs the pkProtocol allowing participants to provide shares and aggregators to aggregate such shares.
func (p *pkProtocol) run(ctx context.Context, session *pkg.Session, env Transport) AggregationOutput {
	log.Printf("%s | [%s] started running with %v\n", p.self, p.ID(), p.Descriptor)

	// pkProtocols can only have one participant: the sender of the public key
	if len(p.Participants) != 1 {
		panic(fmt.Errorf("error: a pkProtocol must have exactly one participant. p.Participants: %v", p.Participants))
	}

	if p.shareProviders.Contains(p.self) {
		kg := rlwe.NewKeyGenerator(*session.Params)
		outputSk := kg.GenSecretKey()
		if err := session.SetOuputSk(outputSk); err != nil {
			panic(err)
		}

		var err error
		p.crp, err = p.proto.ReadCRP(p.crs)
		if err != nil {
			panic(err)
		}

		share := p.proto.AllocateShare()
		share.ProtocolID = p.ID()
		share.Type = p.Type
		share.To = []pkg.NodeID{p.Desc().Aggregator}
		share.From = p.self
		share.Round = 1

		errGen := p.proto.GenShare(outputSk, p.crp, share)
		if errGen != nil {
			panic(errGen)
		}

		env.OutgoingShares() <- share
		log.Printf("%s | [%s] completed participanting\n", p.self, p.ID())
	}

	if p.IsAggregator() {
		select {
		case incShare := <-env.IncomingShares():
			log.Printf("%s | [%s] new share from %s\n", p.self, p.ID(), incShare.From)
			log.Printf("%s | [%s] completed aggregating\n", p.self, p.ID())
			return AggregationOutput{Round: []Share{incShare}}
			// share.
		case <-ctx.Done():
			return AggregationOutput{Error: fmt.Errorf("%s | timeout while aggregating shares for protocol %s, missing: %v", p.self, p.ID(), p.Participants)}
		}
	}

	log.Printf("%s | [%s] completed running\n", p.self, p.ID())
	return AggregationOutput{}
}

// Aggregate runs the protocol and returns a channel through which the output is send.
func (p *pkProtocol) Aggregate(ctx context.Context, session *pkg.Session, env Transport) chan AggregationOutput {
	output := make(chan AggregationOutput)
	go func() {
		output <- p.run(ctx, session, env)
	}()
	return output
}

// Output takes an aggregation output and samples the CRP to reconstruct the Public Key.
func (p *pkProtocol) Output(agg AggregationOutput) chan Output {
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
	log.Printf("%s | [%s] finalized protocol\n", p.self, p.ID())
	out <- Output{Result: res}
	return out
}

func (p *skgProtocol) Aggregate(ctx context.Context, session *pkg.Session, env Transport) chan AggregationOutput {
	output := make(chan AggregationOutput)
	go func() {
		output <- p.aggregate(ctx, session, env)
	}()
	return output
}

func (p *skgProtocol) aggregate(ctx context.Context, session *pkg.Session, env Transport) AggregationOutput {

	log.Printf("%s | [%s] started running with %v\n", p.self, p.ID(), p.Descriptor)

	if !p.shareProviders.Contains(p.self) || session.T == len(session.Nodes) {
		log.Printf("%s | [%s] finalized protocol (N=T)\n", p.self, p.ID())
		return AggregationOutput{}
	}

	sk, err := session.SecretKeyForGroup(p.shareProviders.Elements())
	if err != nil {
		return AggregationOutput{Error: err}
	}

	shamirPoly, err := p.proto.GenShamirPolynomial(session.T, sk)
	if err != nil {
		return AggregationOutput{Error: err}
	}

	ownShare := make(chan Share)
	for nodeID := range p.shareProviders { // TODO: parallel gen
		nodeID := nodeID
		go func() {

			share := p.proto.AllocateShare()
			errGen := p.proto.GenShareForParty(*shamirPoly, session.SPKS[nodeID], share)
			if errGen != nil {
				panic(errGen)
			}
			share.ProtocolID = p.ID()
			share.Type = p.Type
			share.From = p.self
			share.To = []pkg.NodeID{nodeID}
			share.AggregateFor = utils.NewSingletonSet(p.self)
			share.Round = 1
			if nodeID == p.self {
				ownShare <- share
			} else {
				env.OutgoingShares() <- share
			}
		}()

	}

	agg := newShareAggregator(p.shareProviders, <-ownShare, p.proto.AggregatedShares)
	err = p.aggregateShares(ctx, *agg, env) // TODO pointer param
	if err != nil {
		log.Printf("%s | [%s] failed: %s\n", p.self, p.ID(), err)
		return AggregationOutput{Error: err}
	}

	log.Printf("%s | [%s] completed aggregation\n", p.self, p.ID())

	log.Printf("%s | [%s] finalized protocol\n", p.self, p.ID())
	return AggregationOutput{Round: []Share{agg.GetAggregatedShare()}}
}

func (p skgProtocol) Output(agg AggregationOutput) chan Output { // TODO Copy-past from pkProtocol
	out := make(chan Output, 1)
	if agg.Error != nil {
		out <- Output{Error: fmt.Errorf("error at aggregation: %w", agg.Error)}
		return out
	}
	log.Printf("%s | [%s] finalized protocol\n", p.self, p.ID())
	out <- Output{Result: agg.Round[0].MHEShare.(*drlwe.ShamirSecretShare)}
	return out
}

func (p *rkgProtocol) Aggregate(ctx context.Context, session *pkg.Session, env Transport) chan AggregationOutput {
	output := make(chan AggregationOutput)
	go func() {
		output <- p.run(ctx, session, env)
	}()
	return output
}

// run runs the rkgProtocol allowing participants to provide shares and aggregators to aggregate such shares.
func (p *rkgProtocol) run(ctx context.Context, session *pkg.Session, env Transport) AggregationOutput {

	log.Printf("%s | [%s] started running with %v\n", p.self, p.ID(), p.Descriptor)

	var err error
	p.crp, err = p.proto.ReadCRP(session.GetCRSForProtocol(p.ID()))
	if err != nil {
		panic(err)
	}

	var ephSk *rlwe.SecretKey
	var shareR1, shareR2 Share
	if p.IsAggregator() || p.shareProviders.Contains(p.self) {
		ephSk, shareR1, shareR2 = p.proto.AllocateShare()
		shareR1.AggregateFor = utils.NewEmptySet[pkg.NodeID]()
		shareR2.AggregateFor = utils.NewEmptySet[pkg.NodeID]()
	}

	if p.shareProviders.Contains(p.self) {
		sk, errSk := session.SecretKeyForGroup(p.shareProviders.Elements())
		if errSk != nil {
			return AggregationOutput{Error: errSk}
		}
		errGen := p.proto.GenShareRoundOne(sk, p.crp, ephSk, shareR1)
		if errGen != nil {
			panic(errGen)
		}
		shareR1.ProtocolID = p.ID()
		shareR1.Type = p.Type
		shareR1.From = p.self
		shareR1.To = []pkg.NodeID{p.Desc().Aggregator}
		shareR1.AggregateFor = utils.NewSingletonSet(p.self)
		shareR1.Round = 1
	}

	if p.IsAggregator() {
		p.agg1 = *newShareAggregator(p.shareProviders, shareR1, p.proto.AggregatedShares)

		errAggr := p.aggregateShares(ctx, p.agg1, env)
		if errAggr != nil {
			log.Printf("%s | [%s] failed: %s\n", p.self, p.ID(), errAggr)
			return AggregationOutput{Error: errAggr}
		}

		log.Printf("%s | [%s] completed round 1 aggregation\n", p.self, p.ID())

		shareR1 = p.agg1.GetAggregatedShare()
		shareR1.ProtocolID = p.ID()
		shareR1.Type = p.Type
		shareR1.From = p.self
		shareR1.To = p.Participants
		shareR1.AggregateFor = p.shareProviders.Copy()
	}

	if p.IsAggregator() || p.shareProviders.Contains(p.self) {
		env.OutgoingShares() <- shareR1
	}

	// === ROUND 2 ====

	var aggR1 Share

	if p.shareProviders.Contains(p.self) {
		select {
		case aggR1 = <-env.IncomingShares():
		case <-ctx.Done():
			err = fmt.Errorf("%s | timeout while waiting for round 1 aggregated share for protocol %s", p.self, p.ID())
			return AggregationOutput{Error: err}
		}
		log.Printf("%s | got round 1 aggregated share\n", p.self)
	}

	if p.shareProviders.Contains(p.self) {

		sk, errSk := session.SecretKeyForGroup(p.shareProviders.Elements())
		if errSk != nil {
			return AggregationOutput{Error: errSk}
		}

		errGen := p.proto.GenShareRoundTwo(ephSk, sk, aggR1, shareR2)
		if errGen != nil {
			panic(errGen)
		}
		shareR2.ProtocolID = p.ID()
		shareR2.Type = p.Type
		shareR2.From = p.self
		shareR2.To = []pkg.NodeID{p.Desc().Aggregator}
		shareR2.AggregateFor = utils.NewSingletonSet(p.self)
		shareR2.Round = 2
	}

	if p.IsAggregator() {
		p.agg2 = *newShareAggregator(p.shareProviders, shareR2, p.proto.AggregatedShares)

		errAggr := p.aggregateShares(ctx, p.agg2, env)
		if errAggr != nil {
			log.Printf("%s | [%s] failed: %s\n", p.self, p.ID(), errAggr)
			return AggregationOutput{Error: errAggr}
		}

		log.Printf("%s | [%s] completed round 2 aggregation\n", p.self, p.ID())

		shareR2 = p.agg2.GetAggregatedShare()
		shareR2.ProtocolID = p.ID()
		shareR2.Type = p.Type
		shareR2.From = p.self
		shareR2.AggregateFor = p.shareProviders.Copy()
		log.Printf("%s | [%s] completed aggregation\n", p.self, p.ID())
		return AggregationOutput{Round: []Share{shareR1, shareR2}}
	}

	if p.shareProviders.Contains(p.self) {
		env.OutgoingShares() <- shareR2
	}
	log.Printf("%s | [%s] completed aggregation\n", p.self, p.ID())
	return AggregationOutput{}
}

func (p rkgProtocol) Output(agg AggregationOutput) chan Output { // TODO Copy-past from pkProtocol
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
	log.Printf("%s | [%s] finalized protocol\n", p.self, p.ID())
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

func (p *rkgProtocol) AllocateShare() Share {
	_, s, _ := p.proto.AllocateShare()
	return s
}

func (p protocol) aggregateShares(ctx context.Context, aggregator shareAggregator, env Transport) error {
	for {
		select {
		case share := <-env.IncomingShares():
			log.Printf("%s | [%s] new share from %s\n", p.self, p.ID(), share.From)
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
	return p.Descriptor.Aggregator == p.self || p.Descriptor.Type == SKG
}

func (pd Descriptor) String() string {
	return fmt.Sprintf("{ID: %v, Type: %v, Args: %v, Aggregator: %v, Participants: %v}",
		pd.ID, pd.Type, pd.Args, pd.Aggregator, pd.Participants)
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
