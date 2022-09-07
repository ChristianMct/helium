package setup

import (
	"encoding"
	"fmt"
	pkg "helium/pkg/session"
	"helium/pkg/utils"
	"log"
	"strconv"

	"github.com/tuneinsight/lattigo/v3/drlwe"
	"github.com/tuneinsight/lattigo/v3/rlwe"
)

// func (s *Share[S]) MarshalBinary() (data []byte, err error) {
// 	share := s.s
// 	data, err = share.MarshalBinary()
// 	return
// }

type ProtocolInt interface {
	Descriptor() ProtocolDescriptor
	Init(pd ProtocolDescriptor, session *pkg.Session) error
	Rounds() int
	Required(round int) utils.Set[pkg.NodeID]
	GetShare(ShareRequest) (AggregatedShareInt, error)
	PutShare(AggregatedShareInt) (bool, error)
}

type ProtocolShare interface {
	*drlwe.ShamirSecretShare | *drlwe.CKGShare | *drlwe.RKGShare | *drlwe.RTGShare
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

type protocol struct {
	ProtocolDescriptor

	ID   ProtocolID
	self pkg.NodeID

	session *pkg.Session
}

func (p *protocol) Init(session *pkg.Session) error {
	p.session = session
	p.self = session.NodeID

	return nil
}

func (p *protocol) Descriptor() ProtocolDescriptor {
	return p.ProtocolDescriptor // TODO copy
}

func (p *protocol) Rounds() int {
	return 1
}

type SKGProtocol struct {
	protocol
	*drlwe.Thresholdizer

	*drlwe.ShamirPolynomial

	*AggregatorOf[*drlwe.ShamirSecretShare]
}

func (skgp *SKGProtocol) Init(pd ProtocolDescriptor, session *pkg.Session) (err error) {
	skgp.protocol.Init(session)

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

	return
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

func (ckgp *CKGProtocol) Init(pd ProtocolDescriptor, session *pkg.Session) (err error) {
	ckgp.protocol.Init(session)

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
	complete, err := ckgp.AggregatorOf.PutShare(ckgShare)
	if err != nil {
		return false, err
	}
	if complete {
		ckgp.done(ckgp.session)
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

func (rtgp *RTGProtocol) Init(pd ProtocolDescriptor, session *pkg.Session) (err error) {
	rtgp.protocol.Init(session)

	if _, hasArg := rtgp.Args["GalEl"]; !hasArg {
		return fmt.Errorf("should provide argument: GalEl")
	}

	rtgp.galEl, err = strconv.ParseUint(rtgp.Args["GalEl"], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid galois element: %s", err)
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
	complete, err := rtgp.AggregatorOf.PutShare(rtgShare)
	if err != nil {
		return false, err
	}
	if complete {
		rtgp.done()
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

func (rkgp *RKGProtocol) Init(pd ProtocolDescriptor, session *pkg.Session) (err error) {
	rkgp.protocol.Init(session)

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
			share, err = &AggregatedShare[*drlwe.RKGShare]{s: rkgp.shareR1, aggregateFor: utils.NewSingletonSet(rkgp.self)}, nil
		case req.Round == 2 && req.Previous != nil:
			var prevShare drlwe.RKGShare
			prevShare.UnmarshalBinary(req.Previous)

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
	//rkgp.replies <- ProtocolFetchShareTaskResult{share: share, ProtocolFetchShareTasks: ProtocolFetchShareTasks{ShareRequest: ShareRequest{To: senderID}}}

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
			rkgp.done(rkgp.session)
		}

	}

	return isDone, nil
}

func (rkgp *RKGProtocol) done(session *pkg.Session) error {
	log.Printf("Node %s | RKG DONE\n", rkgp.self)
	rkgp.session.RelinearizationKey = rlwe.NewRelinKey(*rkgp.session.Params, 2)
	rkgp.GenRelinearizationKey(rkgp.aggR1.aggShare, rkgp.aggR2.aggShare, rkgp.session.RelinearizationKey)
	return nil
}
