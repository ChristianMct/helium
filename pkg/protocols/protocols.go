package protocols

import (
	"context"
	"fmt"
	"log"

	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v4/drlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

type Descriptor struct {
	Type Type
	Args map[string]interface{}

	Aggregator              pkg.NodeID
	Participants, Receivers []pkg.NodeID
}

type ShareDescriptor struct {
	pkg.ProtocolID
	Type
	Round        uint64
	From         pkg.NodeID
	To           pkg.NodeID
	AggregateFor utils.Set[pkg.NodeID]
}

type Share struct {
	ShareDescriptor
	MHEShare LattigoShare
}

type Input interface{}

type OutputKey interface{}

type CRP interface{}

type Instance interface {
	ID() pkg.ProtocolID
	Desc() Descriptor

	Run(ctx context.Context, session *pkg.Session, env Environment)
}

type KeySwitchInstance interface {
	Instance
	Input(ct *rlwe.Ciphertext)
	Output() chan *rlwe.Ciphertext
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
)

var typeToString = []string{"Unknown", "SKG", "CKG", "RKG", "RTG", "CKS", "DEC", "PCKS"}

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
	default:
		return nil
	}
}

type ProtocolStatus int8

const (
	Created ProtocolStatus = iota
	Running
	Completed
	Failed
)

type protocol struct {
	pkg.ProtocolID
	Descriptor
	status ProtocolStatus

	self      pkg.NodeID
	receivers utils.Set[pkg.NodeID]

	shareProviders chan utils.Set[pkg.NodeID]
}

type skgProtocol struct {
	*protocol
	proto SKGProtocol
}

type pkProtocol struct {
	*protocol
	proto LattigoKeygenProtocol
	agg   shareAggregator
	crp   chan CRP
}

type rkgProtocol struct {
	*protocol
	proto      *RKGProtocol
	agg1, agg2 shareAggregator
	crp        chan CRP
}

type keySwitchProtocol struct {
	*protocol
	proto         LattigoKeySwitchProtocol
	target        pkg.NodeID
	outputKey     OutputKey
	agg           shareAggregator
	input, output chan *rlwe.Ciphertext
}

func NewProtocol(pd Descriptor, sess *pkg.Session, id pkg.ProtocolID) (Instance, error) {
	switch pd.Type {
	case SKG:
		p := newProtocol(pd, sess, id)
		return &skgProtocol{protocol: p, proto: SKGProtocol{Thresholdizer: *drlwe.NewThresholdizer(*sess.Params)}}, nil
	case CKG, RTG, RKG:
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
	p.status = Created

	var receivers []pkg.NodeID
	if len(pd.Receivers) == 0 {
		receivers = sess.Nodes
	} else {
		receivers = pd.Receivers
	}
	p.receivers = utils.NewSet(receivers)

	p.shareProviders = make(chan utils.Set[pkg.NodeID], 1)
	return p
}

func NewKeygenProtocol(pd Descriptor, sess *pkg.Session, id pkg.ProtocolID) (Instance, error) {
	var err error
	var inst Instance
	protocol := newProtocol(pd, sess, id)
	var p *pkProtocol
	switch pd.Type {
	case CKG:
		p = new(pkProtocol)
		p.protocol = protocol
		p.crp = make(chan CRP, 1)
		p.proto, err = NewCKGProtocol(*sess.Params, pd.Args)
		inst = p
	case RTG:
		p = new(pkProtocol)
		p.protocol = protocol
		p.crp = make(chan CRP, 1)
		p.proto, err = NewRTGProtocol(*sess.Params, pd.Args)
		inst = p
	case RKG:
		p := new(rkgProtocol)
		p.protocol = protocol
		p.crp = make(chan CRP, 1)
		p.proto, err = NewRKGProtocol(*sess.Params, pd.Args)
		inst = p
	}
	if err != nil {
		inst = nil
	}
	return inst, err
}

func NewKeyswitchProtocol(pd Descriptor, sess *pkg.Session, id pkg.ProtocolID) (KeySwitchInstance, error) {

	if _, hasArg := pd.Args["target"]; !hasArg {
		return nil, fmt.Errorf("should provide argument: target")
	}
	target, isString := pd.Args["target"].(string)
	if !isString {
		return nil, fmt.Errorf("invalid target type %T instead of %T", pd.Args["target"], target)
	}

	ks := new(keySwitchProtocol)
	ks.target = pkg.NodeID(target)
	ks.input = make(chan *rlwe.Ciphertext, 1)
	ks.output = make(chan *rlwe.Ciphertext, 1)

	ks.protocol = newProtocol(pd, sess, id)
	var err error
	switch pd.Type {
	case CKS:
		return nil, fmt.Errorf("generic standalone CKS protocol not supported yet") // TODO
	case DEC:
		ks.proto, err = NewCKSProtocol(*sess.Params, pd.Args)
		ks.outputKey = rlwe.NewSecretKey(*sess.Params) // target key is zero for decryption
	case PCKS:
		targetPk, exists := sess.GetPkForNode(ks.target)
		if !exists {
			return nil, fmt.Errorf("no pk for node with id %s", target)
		}
		ks.proto, err = NewPCKSProtocol(*sess.Params, pd.Args)
		ks.outputKey = &targetPk
	}
	if err != nil {
		ks = nil
	}
	return ks, err
}

func (p *keySwitchProtocol) Run(ctx context.Context, session *pkg.Session, env Environment) {
	log.Printf("%s | [%s] started running with %v\n", p.self, p.ID(), p.Descriptor)

	part := utils.NewSet(p.Descriptor.Participants) // TODO: reads from protomap for now
	if p.Descriptor.Type == CKS || p.Descriptor.Type == DEC {
		part.Remove(p.target)
	}

	p.shareProviders <- part

	shareProviders := <-p.shareProviders

	inputCt := <-p.input

	var share Share
	if p.IsAggregator() || shareProviders.Contains(p.self) {
		share = p.proto.AllocateShare()
		share.AggregateFor = utils.NewEmptySet[pkg.NodeID]()
	}

	if shareProviders.Contains(p.self) {
		sk, err := session.SecretKeyForGroup(p.Descriptor.Participants)
		if err != nil {
			p.status = Failed
			panic(err)
		}
		err = p.proto.GenShare(sk, p.outputKey, inputCt, share)
		if err != nil {
			panic(err)
		}
		share.ProtocolID = p.ID()
		share.From = p.self
		share.To = p.Desc().Aggregator
		share.AggregateFor = utils.NewSingletonSet(p.self)
		share.Round = 1
	}

	if p.IsAggregator() {
		p.agg = *newShareAggregator(shareProviders, share, p.proto.AggregatedShares)

		err := p.aggregateShares(ctx, p.agg, env)
		if err != nil {
			p.status = Failed
			log.Printf("%s | [%s] failed: %s\n", p.self, p.ID(), err)
			return
		}

		log.Printf("%s | [%s] completed aggregation\n", p.self, p.ID())

		go func() {
			for req := range env.IncomingShareQueries() {
				res := p.agg.GetAggregatedShare()
				req.Result <- res
				close(req.Result)
			}
		}()
	} else if shareProviders.Contains(p.self) {
		env.OutgoingShares() <- share
	}

	if p.IsReceiver() {

		var aggShare Share
		if p.IsAggregator() {
			aggShare = p.agg.GetAggregatedShare()
		} else {
			res := make(chan Share)
			env.ShareQuery(ShareQuery{
				ShareDescriptor: ShareDescriptor{ProtocolID: p.ID(), Type: p.Desc().Type, From: p.Aggregator, To: p.self, Round: 1, AggregateFor: shareProviders.Copy()},
				Result:          res,
			})
			select {
			case aggShare = <-env.IncomingShares():
			case aggShare = <-res:
			case <-ctx.Done():
				p.status = Failed
				log.Println("timeout while aggregating shares")
			}
		}

		outputCt := inputCt.CopyNew()
		err := p.proto.Finalize(inputCt, outputCt, aggShare)
		if err != nil {
			p.status = Failed
			log.Printf("%s | [%s] failed: %s\n", p.self, p.ID(), err)
			return
		}
		log.Printf("%s | [%s] finalized protocol\n", p.self, p.ID())
		p.output <- outputCt
	}

	log.Printf("%s | [%s] completed protocol\n", p.self, p.ID())
}

func (p *pkProtocol) Run(ctx context.Context, session *pkg.Session, env Environment) {

	log.Printf("%s | [%s] started running with %v\n", p.self, p.ID(), p.Descriptor)
	p.shareProviders <- utils.NewSet(p.Descriptor.Participants) // TODO: reads from protomap for now
	shareProviders := <-p.shareProviders

	crp, err := p.proto.ReadCRP(session.GetCRSForProtocol(p.ID()))
	if err != nil {
		panic(err)
	}
	p.crp <- crp
	input := <-p.crp

	var share Share
	if p.IsAggregator() || shareProviders.Contains(p.self) {
		share = p.proto.AllocateShare()
		share.AggregateFor = utils.NewEmptySet[pkg.NodeID]()
	}

	if shareProviders.Contains(p.self) {
		sk, errSk := session.SecretKeyForGroup(shareProviders.Elements())
		if errSk != nil {
			p.status = Failed
			return
		}
		errGen := p.proto.GenShare(sk, input, share)
		if errGen != nil {
			panic(errGen)
		}
		share.ProtocolID = p.ID()
		share.From = p.self
		share.To = p.Desc().Aggregator
		share.AggregateFor = utils.NewSingletonSet(p.self)
		share.Round = 1
	}

	if p.IsAggregator() {
		p.agg = *newShareAggregator(shareProviders, share, p.proto.AggregatedShares)

		errAggr := p.aggregateShares(ctx, p.agg, env)
		if errAggr != nil {
			p.status = Failed
			log.Printf("%s | [%s] failed: %s\n", p.self, p.ID(), errAggr)
			return
		}

		log.Printf("%s | [%s] completed aggregation\n", p.self, p.ID())

		go func() {
			for req := range env.IncomingShareQueries() {
				res := p.agg.GetAggregatedShare() // TODO assume is the right share
				req.Result <- res
				close(req.Result)
			}
		}()
	} else if shareProviders.Contains(p.self) {
		env.OutgoingShares() <- share
	}

	if p.IsReceiver() {

		var aggShare Share
		if p.IsAggregator() {
			aggShare = p.agg.GetAggregatedShare()
		} else {
			res := make(chan Share)
			env.ShareQuery(ShareQuery{
				ShareDescriptor: ShareDescriptor{ProtocolID: p.ID(), Type: p.Desc().Type, From: p.Aggregator, To: p.self, Round: 1, AggregateFor: shareProviders.Copy()},
				Result:          res,
			})
			select {
			case aggShare = <-env.IncomingShares():
			case aggShare = <-res:
			case <-ctx.Done():
				p.status = Failed
				log.Println("timeout while aggregating shares")
			}
		}

		err = p.proto.Finalize(session, input, aggShare)
		if err != nil {
			p.status = Failed
			log.Printf("%s | [%s] failed: %s\n", p.self, p.ID(), err)
			return
		}
		log.Printf("%s | [%s] finalized protocol\n", p.self, p.ID())
	}
	log.Printf("%s | [%s] completed protocol\n", p.self, p.ID())

}

func (p *skgProtocol) Run(ctx context.Context, session *pkg.Session, env Environment) {
	p.shareProviders <- utils.NewSet(p.Descriptor.Participants) // TODO: reads from protomap for now
	shareProviders := <-p.shareProviders

	if !shareProviders.Contains(p.self) {
		return
	}

	sk, err := session.SecretKeyForGroup(shareProviders.Elements())
	if err != nil {
		p.status = Failed
		return
	}

	shamirPoly, err := p.proto.GenShamirPolynomial(session.T, sk)
	if err != nil {
		p.status = Failed
		return
	}

	var ownShare Share
	for nodeID := range shareProviders { // TODO: parallel gen
		share := p.proto.AllocateShare()
		errGen := p.proto.GenShareForParty(*shamirPoly, session.SPKS[nodeID], share)
		if errGen != nil {
			panic(errGen)
		}
		share.ProtocolID = p.ID()
		share.From = p.self
		share.To = nodeID
		share.AggregateFor = utils.NewSingletonSet(p.self)
		share.Round = 1
		if nodeID == p.self {
			ownShare = share
		} else {
			env.OutgoingShares() <- share
		}
	}

	agg := newShareAggregator(shareProviders, ownShare, p.proto.AggregatedShares)
	err = p.aggregateShares(ctx, *agg, env) // TODO pointer param
	if err != nil {
		p.status = Failed
		log.Printf("%s | [%s] failed: %s\n", p.self, p.ID(), err)
		return
	}

	log.Printf("%s | [%s] completed aggregation\n", p.self, p.ID())

	errFin := p.proto.Finalize(session, agg.share)
	if errFin != nil {
		panic(errFin)
	}

	log.Printf("%s | [%s] finalized protocol\n", p.self, p.ID())
}

func (p *rkgProtocol) Run(ctx context.Context, session *pkg.Session, env Environment) {

	log.Printf("%s | [%s] started running with %v\n", p.self, p.ID(), p.Descriptor)
	p.shareProviders <- utils.NewSet(p.Descriptor.Participants) // TODO: reads from protomap for now
	shareProviders := <-p.shareProviders

	crp, err := p.proto.ReadCRP(session.GetCRSForProtocol(p.ID()))
	if err != nil {
		panic(err)
	}
	p.crp <- crp
	input := <-p.crp

	var ephSk *rlwe.SecretKey
	var shareR1, shareR2 Share
	if p.IsAggregator() || shareProviders.Contains(p.self) {
		ephSk, shareR1, shareR2 = p.proto.AllocateShare()
		shareR1.AggregateFor = utils.NewEmptySet[pkg.NodeID]()
		shareR2.AggregateFor = utils.NewEmptySet[pkg.NodeID]()
	}

	if shareProviders.Contains(p.self) {
		sk, errSk := session.SecretKeyForGroup(shareProviders.Elements())
		if errSk != nil {
			p.status = Failed
			return
		}
		errGen := p.proto.GenShareRoundOne(sk, crp, ephSk, shareR1)
		if errGen != nil {
			panic(errGen)
		}
		shareR1.ProtocolID = p.ID()
		shareR1.From = p.self
		shareR1.To = p.Desc().Aggregator
		shareR1.AggregateFor = utils.NewSingletonSet(p.self)
		shareR1.Round = 1
	}

	agg1Requests := make(chan ShareQuery, 1024) // TODO sizing
	agg2Requests := make(chan ShareQuery, 1024)
	go func() {
		for req := range env.IncomingShareQueries() {
			switch req.ShareDescriptor.Round {
			case 1:
				agg1Requests <- req
			case 2:
				agg2Requests <- req
			}
		}
	}()

	if p.IsAggregator() {
		p.agg1 = *newShareAggregator(shareProviders, shareR1, p.proto.AggregatedShares)

		errAggr := p.aggregateShares(ctx, p.agg1, env)
		if errAggr != nil {
			p.status = Failed
			log.Printf("%s | [%s] failed: %s\n", p.self, p.ID(), errAggr)
			return
		}

		log.Printf("%s | [%s] completed round 1 aggregation\n", p.self, p.ID())

		go func() {
			for req := range agg1Requests {
				res := p.agg1.GetAggregatedShare() // TODO assume is the right share
				req.Result <- res
				close(req.Result)
			}
		}()
	} else if shareProviders.Contains(p.self) {
		env.OutgoingShares() <- shareR1
	}

	// === ROUND 2 ====

	var aggR1 Share

	if shareProviders.Contains(p.self) || p.IsReceiver() {
		if p.IsAggregator() {
			aggR1 = p.agg1.GetAggregatedShare()
		} else {
			res := make(chan Share)
			env.ShareQuery(ShareQuery{
				ShareDescriptor: ShareDescriptor{ProtocolID: p.ID(), Type: p.Desc().Type, From: p.Aggregator, To: p.self, Round: 1, AggregateFor: shareProviders.Copy()},
				Result:          res,
			})
			select {
			case aggR1 = <-env.IncomingShares():
			case aggR1 = <-res:
			case <-ctx.Done():
				p.status = Failed
				log.Println("timeout while aggregating shares")
			}
		}
	}

	if shareProviders.Contains(p.self) {

		sk, errSk := session.SecretKeyForGroup(shareProviders.Elements())
		if errSk != nil {
			p.status = Failed
			return
		}

		errGen := p.proto.GenShareRoundTwo(ephSk, sk, aggR1, shareR2)
		if errGen != nil {
			panic(errGen)
		}
		shareR2.ProtocolID = p.ID()
		shareR2.From = p.self
		shareR2.To = p.Desc().Aggregator
		shareR2.AggregateFor = utils.NewSingletonSet(p.self)
		shareR2.Round = 2
	}

	if p.IsAggregator() {
		p.agg2 = *newShareAggregator(shareProviders, shareR2, p.proto.AggregatedShares)

		errAggr := p.aggregateShares(ctx, p.agg2, env)
		if errAggr != nil {
			p.status = Failed
			log.Printf("%s | [%s] failed: %s\n", p.self, p.ID(), errAggr)
			return
		}

		log.Printf("%s | [%s] completed round 2 aggregation\n", p.self, p.ID())

		go func() {
			for req := range agg2Requests {
				res := p.agg2.GetAggregatedShare() // TODO assume is the right share
				req.Result <- res
				close(req.Result)
			}
		}()
	} else if shareProviders.Contains(p.self) {
		env.OutgoingShares() <- shareR2
	}

	if p.IsReceiver() {

		var aggR2 Share
		if p.IsAggregator() {
			aggR2 = p.agg2.GetAggregatedShare()
		} else {
			res := make(chan Share)
			env.ShareQuery(ShareQuery{
				ShareDescriptor: ShareDescriptor{ProtocolID: p.ID(), Type: p.Desc().Type, From: p.Aggregator, To: p.self, Round: 2, AggregateFor: shareProviders.Copy()},
				Result:          res,
			})
			select {
			case aggR2 = <-env.IncomingShares():
			case aggR2 = <-res:
			case <-ctx.Done():
				p.status = Failed
				log.Println("timeout while aggregating shares")
			}
		}

		errFin := p.proto.Finalize(session, input, aggR1, aggR2)
		if errFin != nil {
			p.status = Failed
			log.Printf("%s | [%s] failed: %s\n", p.self, p.ID(), errFin)
			return
		}
		log.Printf("%s | [%s] finalized protocol\n", p.self, p.ID())
	}
	log.Printf("%s | [%s] completed protocol\n", p.self, p.ID())
}

func (p *keySwitchProtocol) Input(ct *rlwe.Ciphertext) {
	p.input <- ct
}

func (p *keySwitchProtocol) Output() chan *rlwe.Ciphertext {
	return p.output
}

func (p *protocol) ID() pkg.ProtocolID {
	return p.ProtocolID
}

func (p *protocol) Desc() Descriptor {
	return p.Descriptor
}

func (p *pkProtocol) AllocateShare() Share {
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

func (p protocol) aggregateShares(ctx context.Context, aggregator shareAggregator, env Environment) error {
	for {
		select {
		case share := <-env.IncomingShares():
			done, err := aggregator.PutShare(share)
			if err != nil {
				return err
			}
			if done {
				return nil
			}
		case <-ctx.Done():
			return fmt.Errorf("timeout while aggregating shares")
		}
	}
}

func (p *protocol) IsAggregator() bool {
	return p.Descriptor.Aggregator == p.self || p.Descriptor.Type == SKG
}

func (p *protocol) IsReceiver() bool {
	return p.receivers.Contains(p.self)
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
