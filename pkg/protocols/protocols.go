package protocols

import (
	"encoding"
	"fmt"
	"log"
	"strconv"

	"github.com/ldsec/helium/pkg/api"
	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v3/drlwe"
	"github.com/tuneinsight/lattigo/v3/rlwe"
)

type Descriptor struct {
	Type         api.ProtocolType
	Args         map[string]string
	Aggregator   pkg.NodeID
	Participants []pkg.NodeID
}

type ShareRequest struct {
	pkg.ProtocolID
	From         pkg.NodeID
	To           pkg.NodeID
	Round        uint64
	Previous     []byte
	AggregateFor []pkg.NodeID
	NoData       bool
}

func (s ShareRequest) String() string {
	return fmt.Sprintf("ShareRequest[protocol_id: %s from: %s to: %s has_previous: %v]", s.ProtocolID, s.From, s.To, len(s.Previous) > 0)
}

type Interface interface {
	Desc() Descriptor
	Init(pd Descriptor, session *pkg.Session) error
	Rounds() int
	Required(round int) utils.Set[pkg.NodeID]
	GetShare(ShareRequest) (AggregatedShareInt, error)
	PutShare(AggregatedShareInt) (bool, error)
}

type Share interface {
	*drlwe.ShamirSecretShare | *drlwe.CKGShare | *drlwe.RKGShare | *drlwe.RTGShare | *drlwe.CKSShare | *drlwe.PCKSShare
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

type protocol struct {
	Descriptor
	self pkg.NodeID

	session *pkg.Session
}

func (p *protocol) Init(session *pkg.Session) error {
	p.session = session
	p.self = session.NodeID

	return nil
}

func (p *protocol) Desc() Descriptor {
	return p.Descriptor // TODO copy
}

func (p *protocol) Rounds() int {
	return 1
}

func New(protoDesc Descriptor, session *pkg.Session) (Interface, error) {
	var proto Interface
	switch protoDesc.Type {
	case api.ProtocolType_SKG:
		proto = &SKGProtocol{
			protocol:      protocol{Descriptor: protoDesc},
			Thresholdizer: drlwe.NewThresholdizer(*session.Params),
		}
	case api.ProtocolType_CKG:
		proto = &CKGProtocol{
			protocol:    protocol{Descriptor: protoDesc},
			CKGProtocol: *drlwe.NewCKGProtocol(*session.Params)}

	case api.ProtocolType_RTG:
		proto = &RTGProtocol{
			protocol:    protocol{Descriptor: protoDesc},
			RTGProtocol: *drlwe.NewRTGProtocol(*session.Params),
		}
	case api.ProtocolType_RKG:
		proto = &RKGProtocol{
			protocol:    protocol{Descriptor: protoDesc},
			RKGProtocol: *drlwe.NewRKGProtocol(*session.Params)}

	default:
		return nil, fmt.Errorf("unknown type %s was skipped", protoDesc.Type)
	}

	if err := proto.Init(protoDesc, session); err != nil {
		return nil, err
	}

	return proto, nil
}

type SKGProtocol struct {
	protocol
	*drlwe.Thresholdizer

	*drlwe.ShamirPolynomial

	*AggregatorOf[*drlwe.ShamirSecretShare]
}

func (skgp *SKGProtocol) Init(pd Descriptor, session *pkg.Session) (err error) {
	err = skgp.protocol.Init(session)
	if err != nil {
		log.Printf("failed to init proto: %v", err)
		return err
	}

	skgp.Thresholdizer = drlwe.NewThresholdizer(*session.Params)

	sk, err := session.SecretKeyForGroup(pd.Participants)
	if err != nil {
		return err
	}
	skgp.ShamirPolynomial, err = skgp.Thresholdizer.GenShamirPolynomial(session.T, sk)
	if err != nil {
		return err
	}

	skgp.AggregatorOf = NewAggregatorOf[*drlwe.ShamirSecretShare](utils.NewSet(session.Nodes), skgp.AllocateThresholdSecretShare(), skgp.Thresholdizer)

	ownShare := skgp.AllocateThresholdSecretShare()
	skgp.GenShamirSecretShare(session.SPKS[skgp.self], skgp.ShamirPolynomial, ownShare)

	_, err = skgp.AggregatorOf.PutShare(&AggregatedShare[*drlwe.ShamirSecretShare]{s: ownShare, aggregateFor: utils.NewSet([]pkg.NodeID{skgp.self})})
	if err != nil {
		return err
	}

	return err
}

func (skgp *SKGProtocol) Required(round int) (nodeIds utils.Set[pkg.NodeID]) {
	nodeIds = utils.NewEmptySet[pkg.NodeID]()
	if round == 1 {
		for peer := range skgp.expected {
			if !skgp.aggregated.Contains(peer) {
				nodeIds.Add(peer)
			}
		}
	}
	return nodeIds
}

func (skgp *SKGProtocol) GetShare(sr ShareRequest) (AggregatedShareInt, error) {

	switch {
	case len(sr.AggregateFor) == 0:
		return &AggregatedShare[*drlwe.ShamirSecretShare]{s: skgp.AllocateThresholdSecretShare(), aggregateFor: utils.NewEmptySet[pkg.NodeID]()}, nil
	case len(sr.AggregateFor) == 1 && sr.AggregateFor[0] == skgp.self:
		shamirPk, exists := skgp.session.SPKS[sr.From]
		if !exists {
			return nil, fmt.Errorf("no shamir pk for node with id %s", sr.From)
		}

		shareOut := skgp.AllocateThresholdSecretShare()
		skgp.GenShamirSecretShare(shamirPk, skgp.ShamirPolynomial, shareOut)

		return &AggregatedShare[*drlwe.ShamirSecretShare]{s: shareOut, aggregateFor: utils.NewSingletonSet(skgp.self)}, nil
	default:
		panic("not yet supported")
	}

}

func (skgp *SKGProtocol) PutShare(share AggregatedShareInt) (bool, error) {
	ckgShare, ok := share.(*AggregatedShare[*drlwe.ShamirSecretShare])
	if !ok {
		return false, fmt.Errorf("invalid share type")
	}
	complete, err := skgp.AggregatorOf.PutShare(ckgShare)
	if err != nil {
		return false, err
	}
	if complete {
		log.Printf("Node %s | SKG DONE\n", skgp.self)
		skgp.session.SetTSK(skgp.aggShare)
	}
	return complete, nil
}

type CKGProtocol struct {
	protocol
	drlwe.CKGProtocol
	*AggregatorOf[*drlwe.CKGShare]

	crp   *drlwe.CKGCRP
	share *drlwe.CKGShare
}

func (ckgp *CKGProtocol) Init(pd Descriptor, session *pkg.Session) (err error) {
	err = ckgp.protocol.Init(session)
	if err != nil {
		log.Printf("failed to init proto: %v", err)
		return err
	}

	crp := ckgp.SampleCRP(session.CRS)
	ckgp.crp = &crp
	participants := utils.NewSet(pd.Participants)

	if pd.Aggregator == ckgp.self {
		ckgp.AggregatorOf = NewAggregatorOf[*drlwe.CKGShare](participants, ckgp.AllocateShare(), &ckgp.CKGProtocol)
	}

	return err
}

func (ckgp *CKGProtocol) Required(round int) (nodeIds utils.Set[pkg.NodeID]) {
	nodeIds = utils.NewEmptySet[pkg.NodeID]()
	if round == 1 {
		for peer := range ckgp.expected {
			if !ckgp.aggregated.Contains(peer) {
				nodeIds.Add(peer)
			}
		}
	}
	return nodeIds
}

func (ckgp *CKGProtocol) GetShare(req ShareRequest) (share AggregatedShareInt, err error) {

	switch {
	case len(req.AggregateFor) == 0:
		return &AggregatedShare[*drlwe.CKGShare]{s: ckgp.AllocateShare(), aggregateFor: utils.NewEmptySet[pkg.NodeID]()}, nil
	case len(req.AggregateFor) == 1 && req.AggregateFor[0] == ckgp.self:
		sk, err := ckgp.session.SecretKeyForGroup(ckgp.Participants)
		if err != nil {
			return nil, err
		}
		ckgp.share = ckgp.AllocateShare()
		ckgp.GenShare(sk, *ckgp.crp, ckgp.share)
		return &AggregatedShare[*drlwe.CKGShare]{s: ckgp.share, aggregateFor: utils.NewSingletonSet(ckgp.self)}, nil
	default:
		if ckgp.AggregatorOf == nil || !ckgp.AggregatorOf.expected.Equals(utils.NewSet(req.AggregateFor)) {
			return nil, fmt.Errorf("no such aggregator")
		}
		return ckgp.AggregatorOf.GetShare(), nil
	}
}

func (ckgp *CKGProtocol) PutShare(share AggregatedShareInt) (bool, error) {
	ckgShare, ok := share.(*AggregatedShare[*drlwe.CKGShare])
	if !ok {
		return false, fmt.Errorf("invalid share type")
	}

	if ckgp.AggregatorOf == nil {
		return false, fmt.Errorf("no aggregator")
	}
	complete, err := ckgp.AggregatorOf.PutShare(ckgShare)

	if err != nil {
		return false, err
	}
	if complete {
		err := ckgp.done(ckgp.session)
		if err != nil {
			return false, fmt.Errorf("failed to complete protocol: %w", err)
		}
	}
	return complete, nil
}

func (ckgp *CKGProtocol) done(session *pkg.Session) (err error) {
	log.Printf("Node %s | CKG DONE\n", ckgp.self)
	session.PublicKey = rlwe.NewPublicKey(*session.Params)
	ckgp.GenPublicKey(ckgp.aggShare, *ckgp.crp, session.PublicKey)
	return nil
}

type RTGProtocol struct {
	protocol
	drlwe.RTGProtocol // TODO come back to drlwe type when Lattigo is fixed
	*AggregatorOf[*drlwe.RTGShare]

	galEl  uint64
	crp    *drlwe.RTGCRP
	share  *drlwe.RTGShare
	rotkey *rlwe.RotationKeySet
}

func (rtgp *RTGProtocol) Init(pd Descriptor, session *pkg.Session) (err error) {
	err = rtgp.protocol.Init(session)
	if err != nil {
		log.Printf("failed to init proto: %v", err)
		return err
	}

	if _, hasArg := rtgp.Args["GalEl"]; !hasArg {
		return fmt.Errorf("should provide argument: GalEl")
	}

	rtgp.galEl, err = strconv.ParseUint(rtgp.Args["GalEl"], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid galois element: %w", err)
	}

	crp := rtgp.SampleCRP(session.CRS)
	rtgp.crp = &crp
	participants := utils.NewSet(pd.Participants)

	if pd.Aggregator == rtgp.self {
		rtgp.AggregatorOf = NewAggregatorOf[*drlwe.RTGShare](participants, rtgp.AllocateShare(), &rtgp.RTGProtocol)
	}

	return err
}

func (rtgp *RTGProtocol) Required(round int) (nodeIds utils.Set[pkg.NodeID]) {
	nodeIds = utils.NewEmptySet[pkg.NodeID]()
	if round == 1 {
		for peer := range rtgp.expected {
			if !rtgp.aggregated.Contains(peer) {
				nodeIds.Add(peer)
			}
		}
	}
	return nodeIds
}

func (rtgp *RTGProtocol) GetShare(req ShareRequest) (share AggregatedShareInt, err error) {

	switch {
	case len(req.AggregateFor) == 0:
		return &AggregatedShare[*drlwe.RTGShare]{s: rtgp.AllocateShare(), aggregateFor: utils.NewEmptySet[pkg.NodeID]()}, nil
	case len(req.AggregateFor) == 1 && req.AggregateFor[0] == rtgp.self:
		sk, err := rtgp.session.SecretKeyForGroup(rtgp.Participants)
		if err != nil {
			return nil, err
		}
		rtgp.share = rtgp.AllocateShare()
		rtgp.GenShare(sk, rtgp.galEl, *rtgp.crp, rtgp.share)
		return &AggregatedShare[*drlwe.RTGShare]{s: rtgp.share, aggregateFor: utils.NewSingletonSet(rtgp.self)}, nil
	default:
		if rtgp.AggregatorOf == nil || !rtgp.AggregatorOf.expected.Equals(utils.NewSet(req.AggregateFor)) {
			return nil, fmt.Errorf("no such aggregator")
		}
		return rtgp.AggregatorOf.GetShare(), nil
	}

}

func (rtgp *RTGProtocol) PutShare(share AggregatedShareInt) (bool, error) {
	rtgShare, ok := share.(*AggregatedShare[*drlwe.RTGShare])
	if !ok {
		return false, fmt.Errorf("invalid share type")
	}

	if rtgp.AggregatorOf == nil {
		return false, fmt.Errorf("missing aggregator")
	}

	complete, err := rtgp.AggregatorOf.PutShare(rtgShare)
	if err != nil {
		return false, err
	}
	if complete {
		err := rtgp.done()
		if err != nil {
			return false, fmt.Errorf("failed to complete protocol: %w", err)
		}
	}
	return complete, nil
}

func (rtgp *RTGProtocol) done() (err error) {
	log.Printf("Node %s | RTG DONE\n", rtgp.self)
	params := *rtgp.session.Params
	rtgp.rotkey = rlwe.NewRotationKeySet(params, []uint64{rtgp.galEl})
	swk := rlwe.NewSwitchingKey(params, params.QCount()-1, params.PCount()-1)
	rtgp.GenRotationKey(rtgp.aggShare, *rtgp.crp, swk)
	rtgp.session.EvaluationKey.Rtks.Keys[rtgp.galEl] = swk
	return nil
}

type RKGProtocol struct {
	protocol
	drlwe.RKGProtocol

	RlkEphemSk   *rlwe.SecretKey
	crp          *drlwe.RKGCRP
	shareR1      *drlwe.RKGShare
	shareR2      *drlwe.RKGShare
	aggR1, aggR2 *AggregatorOf[*drlwe.RKGShare]
}

func (rkgp *RKGProtocol) Init(pd Descriptor, session *pkg.Session) (err error) {
	err = rkgp.protocol.Init(session)
	if err != nil {
		log.Printf("failed to init proto: %v", err)
		return err
	}

	crp := rkgp.SampleCRP(session.CRS)
	rkgp.crp = &crp
	participants := utils.NewSet(pd.Participants)

	if pd.Aggregator == rkgp.self {
		var shareR1, shareR2 *drlwe.RKGShare
		_, shareR1, shareR2 = rkgp.AllocateShare()
		rkgp.aggR1 = NewAggregatorOf[*drlwe.RKGShare](participants, shareR1, &rkgp.RKGProtocol)
		rkgp.aggR2 = NewAggregatorOf[*drlwe.RKGShare](participants, shareR2, &rkgp.RKGProtocol)
	}

	return err
}

func (rkgp *RKGProtocol) Rounds() int {
	return 2
}

func (rkgp *RKGProtocol) Required(round int) (nodeIds utils.Set[pkg.NodeID]) {
	nodeIds = utils.NewEmptySet[pkg.NodeID]()

	var agg *AggregatorOf[*drlwe.RKGShare]
	switch round {
	case 1:
		agg = rkgp.aggR1
	case 2:
		agg = rkgp.aggR2
	default:
		return nodeIds
	}
	for peer := range agg.expected {
		if !agg.aggregated.Contains(peer) {
			nodeIds.Add(peer)
		}
	}
	return nodeIds
}

func (rkgp *RKGProtocol) GetShare(req ShareRequest) (share AggregatedShareInt, err error) {

	switch {
	case len(req.AggregateFor) == 0:
		_, newshare, _ := rkgp.AllocateShare()
		return &AggregatedShare[*drlwe.RKGShare]{s: newshare, aggregateFor: utils.NewEmptySet[pkg.NodeID]()}, nil
	case len(req.AggregateFor) == 1 && req.AggregateFor[0] == rkgp.self:
		switch {
		case req.Round == 1:
			sk, err := rkgp.session.SecretKeyForGroup(rkgp.Participants)
			if err != nil {
				return nil, err
			}
			rkgp.RlkEphemSk, rkgp.shareR1, rkgp.shareR2 = rkgp.AllocateShare()
			rkgp.GenShareRoundOne(sk, *rkgp.crp, rkgp.RlkEphemSk, rkgp.shareR1)
			share = &AggregatedShare[*drlwe.RKGShare]{s: rkgp.shareR1, aggregateFor: utils.NewSingletonSet(rkgp.self)}
		case req.Round == 2 && req.Previous != nil:
			var prevShare drlwe.RKGShare
			err := prevShare.UnmarshalBinary(req.Previous)
			if err != nil {
				log.Printf("failed to unmarshal binary: %v", err)
				return nil, err
			}

			sk, err := rkgp.session.SecretKeyForGroup(rkgp.Participants)
			if err != nil {
				return nil, err
			}

			rkgp.GenShareRoundTwo(rkgp.RlkEphemSk, sk, &prevShare, rkgp.shareR2)
			fallthrough
		case req.Round == 2 && rkgp.shareR2 != nil:
			share, err = &AggregatedShare[*drlwe.RKGShare]{s: rkgp.shareR2, aggregateFor: utils.NewSingletonSet(rkgp.self)}, nil
		default:
			return nil, fmt.Errorf("invalid share request")
		}
	case len(req.AggregateFor) > 1:
		var agg *AggregatorOf[*drlwe.RKGShare]
		switch req.Round {
		case 1:
			agg = rkgp.aggR1
		case 2:
			agg = rkgp.aggR2
		default:
			return nil, fmt.Errorf("invalid share request")
		}
		if agg == nil || !agg.expected.Equals(utils.NewSet(req.AggregateFor)) {
			return nil, fmt.Errorf("no such aggregator")
		}
		return agg.GetShare(), nil
	default:
		return nil, fmt.Errorf("invalid share request")
	}

	return
}

func (rkgp *RKGProtocol) PutShare(share AggregatedShareInt) (bool, error) {
	// rkgp.replies <- ProtocolFetchShareTaskResult{share: share, ProtocolFetchShareTasks: ProtocolFetchShareTasks{ShareRequest: ShareRequest{To: senderID}}}

	agg := rkgp.aggR1
	if rkgp.aggR1.Complete() {
		agg = rkgp.aggR2
	}

	rkgShare, ok := share.(*AggregatedShare[*drlwe.RKGShare])
	if !ok {
		return false, fmt.Errorf("invalid share type")
	}

	isDone, err := agg.PutShare(rkgShare)
	if err != nil {
		return false, err
	}
	if isDone {
		if agg == rkgp.aggR1 {
			if rkgp.aggR2.expected.Contains(rkgp.self) {

				sk, err := rkgp.session.SecretKeyForGroup(rkgp.Participants)
				if err != nil {
					return false, err
				}

				rkgp.GenShareRoundTwo(rkgp.RlkEphemSk, sk, rkgp.aggR1.aggShare, rkgp.shareR2)
			}
		} else {
			err := rkgp.done(rkgp.session)
			if err != nil {
				return false, fmt.Errorf("failed to complete protocol: %w", err)
			}
		}

	}

	return isDone, nil
}

func (rkgp *RKGProtocol) done(session *pkg.Session) error {
	// todo: do we need the session param?
	log.Printf("Node %s | RKG DONE | Session %s\n", rkgp.self, session.ID)
	const maxRelinDegree = 2
	rkgp.session.RelinearizationKey = rlwe.NewRelinKey(*rkgp.session.Params, maxRelinDegree)
	rkgp.GenRelinearizationKey(rkgp.aggR1.aggShare, rkgp.aggR2.aggShare, rkgp.session.RelinearizationKey)
	return nil // todo: do we expect to have error checking or should `done` just not return an error?
}

type CKSProtocol struct {
	protocol
	drlwe.CKSProtocol
	*AggregatorOf[*drlwe.CKSShare]

	// from instanciation
	lvl    int
	target pkg.NodeID
	share  *drlwe.CKSShare

	zero *rlwe.SecretKey

	// runtime
	opIn        *pkg.Operand
	c1in, c1out chan pkg.Operand
}

func NewCKSProtocol(sess *pkg.Session, target pkg.NodeID, lvl int, smudging float64) *CKSProtocol {
	return &CKSProtocol{
		protocol:    protocol{},
		target:      target,
		lvl:         lvl,
		zero:        rlwe.NewSecretKey(*sess.Params),
		CKSProtocol: *drlwe.NewCKSProtocol(*sess.Params, smudging)}
}

func (cksp *CKSProtocol) Init(pd Descriptor, session *pkg.Session) (err error) {
	cksp.protocol.Descriptor = pd
	cksp.protocol.Init(session) // TODO should Init take the pd as input ?

	participants := utils.NewSet(pd.Participants)
	if participants.Contains(cksp.target) { // Target of CKS protocol do not provide a share
		participants.Remove(cksp.target)
	}

	if pd.Aggregator == cksp.self {
		cksp.AggregatorOf = NewAggregatorOf[*drlwe.CKSShare](participants, cksp.AllocateShare(cksp.lvl), &cksp.CKSProtocol)
	}

	if cksp.target != cksp.self {
		cksp.share = cksp.AllocateShare(cksp.lvl)
	}

	cksp.c1in = make(chan pkg.Operand, 1)
	cksp.c1out = make(chan pkg.Operand, 1)
	return err
}

func (cksp *CKSProtocol) Required(round int) (nodeIds utils.Set[pkg.NodeID]) {
	nodeIds = utils.NewEmptySet[pkg.NodeID]()
	if round == 1 {
		for peer := range cksp.expected {
			if !cksp.aggregated.Contains(peer) {
				nodeIds.Add(peer)
			}
		}
	}
	return nodeIds
}

func (cksp *CKSProtocol) GetShare(req ShareRequest) (share AggregatedShareInt, err error) {

	switch {
	case len(req.AggregateFor) == 0:
		return &AggregatedShare[*drlwe.CKSShare]{s: cksp.AllocateShare(cksp.lvl), aggregateFor: utils.NewEmptySet[pkg.NodeID]()}, nil
	case len(req.AggregateFor) == 1 && req.AggregateFor[0] == cksp.self:
		sk, err := cksp.session.SecretKeyForGroup(cksp.Participants)
		if err != nil {
			return nil, err
		}
		if cksp.opIn == nil {
			op := <-cksp.c1in
			cksp.opIn = &op
		}

		cksp.GenShare(sk, cksp.zero, cksp.opIn.Value[1], cksp.share)
		return &AggregatedShare[*drlwe.CKSShare]{s: cksp.share, aggregateFor: utils.NewSingletonSet(cksp.self)}, nil
	default:
		if cksp.AggregatorOf == nil || !cksp.AggregatorOf.expected.Equals(utils.NewSet(req.AggregateFor)) {
			return nil, fmt.Errorf("no such aggregator")
		}
		return cksp.AggregatorOf.GetShare(), nil
	}
}

func (cksp *CKSProtocol) PutShare(share AggregatedShareInt) (bool, error) {
	ckgShare, ok := share.(*AggregatedShare[*drlwe.CKSShare])
	if !ok {
		return false, fmt.Errorf("invalid share type")
	}
	complete, err := cksp.AggregatorOf.PutShare(ckgShare)
	if err != nil {
		return false, err
	}
	if complete {
		if cksp.opIn == nil {
			op := <-cksp.c1in
			cksp.opIn = &op
		}
		ctOut := cksp.opIn.CopyNew()
		cksp.CKSProtocol.KeySwitch(cksp.opIn.Ciphertext.Ciphertext, cksp.aggShare, ctOut.Ciphertext)
		cksp.c1out <- pkg.Operand{OperandLabel: "TODO", Ciphertext: ctOut}
	}
	return complete, nil
}

func (cksp *CKSProtocol) Inputs() chan<- pkg.Operand {
	return cksp.c1in
}

func (cksp *CKSProtocol) Outputs() <-chan pkg.Operand {
	return cksp.c1out
}

func (cksp *CKSProtocol) Target() pkg.NodeID {
	return cksp.target
}

type PCKSProtocol struct {
	protocol
	drlwe.PCKSProtocol
	*AggregatorOf[*drlwe.PCKSShare]

	// from instanciation
	lvl    int
	target pkg.NodeID
	share  *drlwe.PCKSShare

	targetPk *rlwe.PublicKey

	// runtime
	opIn        *pkg.Operand
	c1in, c1out chan pkg.Operand
}

func NewPCKSProtocol(sess *pkg.Session, target pkg.NodeID, lvl int, smudging float64) *PCKSProtocol {
	targetPk, exists := sess.GetPkForNode(target)
	if !exists {
		panic(fmt.Errorf("no pk known for target \"%s\"", target))
	}
	return &PCKSProtocol{
		protocol:     protocol{},
		target:       target,
		lvl:          lvl,
		targetPk:     &targetPk,
		PCKSProtocol: *drlwe.NewPCKSProtocol(*sess.Params, smudging)}
}

func (cksp *PCKSProtocol) Init(pd Descriptor, session *pkg.Session) (err error) {
	cksp.protocol.Descriptor = pd
	cksp.protocol.Init(session) // TODO should Init take the pd as input ?

	participants := utils.NewSet(pd.Participants)

	if pd.Aggregator == cksp.self {
		cksp.AggregatorOf = NewAggregatorOf[*drlwe.PCKSShare](participants, cksp.AllocateShare(cksp.lvl), &cksp.PCKSProtocol)
	}

	cksp.share = cksp.AllocateShare(cksp.lvl)

	cksp.c1in = make(chan pkg.Operand, 1)
	cksp.c1out = make(chan pkg.Operand, 1)
	return err
}

func (pcksp *PCKSProtocol) Required(round int) (nodeIds utils.Set[pkg.NodeID]) {
	nodeIds = utils.NewEmptySet[pkg.NodeID]()
	if round == 1 {
		for peer := range pcksp.expected {
			if !pcksp.aggregated.Contains(peer) {
				nodeIds.Add(peer)
			}
		}
	}
	return nodeIds
}

func (pcksp *PCKSProtocol) GetShare(req ShareRequest) (share AggregatedShareInt, err error) {

	switch {
	case len(req.AggregateFor) == 0:
		return &AggregatedShare[*drlwe.PCKSShare]{s: pcksp.AllocateShare(pcksp.lvl), aggregateFor: utils.NewEmptySet[pkg.NodeID]()}, nil
	case len(req.AggregateFor) == 1 && req.AggregateFor[0] == pcksp.self:
		sk, err := pcksp.session.SecretKeyForGroup(pcksp.Participants)
		if err != nil {
			return nil, err
		}
		if pcksp.opIn == nil {
			op := <-pcksp.c1in
			pcksp.opIn = &op
		}

		pcksp.GenShare(sk, pcksp.targetPk, pcksp.opIn.Value[1], pcksp.share)
		return &AggregatedShare[*drlwe.PCKSShare]{s: pcksp.share, aggregateFor: utils.NewSingletonSet(pcksp.self)}, nil
	default:
		if pcksp.AggregatorOf == nil || !pcksp.AggregatorOf.expected.Equals(utils.NewSet(req.AggregateFor)) {
			return nil, fmt.Errorf("no such aggregator")
		}
		return pcksp.AggregatorOf.GetShare(), nil
	}
}

func (pcksp *PCKSProtocol) PutShare(share AggregatedShareInt) (bool, error) {
	ckgShare, ok := share.(*AggregatedShare[*drlwe.PCKSShare])
	if !ok {
		return false, fmt.Errorf("invalid share type")
	}
	complete, err := pcksp.AggregatorOf.PutShare(ckgShare)
	if err != nil {
		return false, err
	}
	if complete {
		if pcksp.opIn == nil {
			op := <-pcksp.c1in
			pcksp.opIn = &op
		}
		ctOut := pcksp.opIn.CopyNew()
		pcksp.PCKSProtocol.KeySwitch(pcksp.opIn.Ciphertext.Ciphertext, pcksp.aggShare, ctOut.Ciphertext)
		pcksp.c1out <- pkg.Operand{OperandLabel: "TODO", Ciphertext: ctOut}
	}
	return complete, nil
}

func (pcksp *PCKSProtocol) Inputs() chan<- pkg.Operand {
	return pcksp.c1in
}

func (pcksp *PCKSProtocol) Outputs() <-chan pkg.Operand {
	return pcksp.c1out
}

func (pcksp *PCKSProtocol) Target() pkg.NodeID {
	return pcksp.target
}
