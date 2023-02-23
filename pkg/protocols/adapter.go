package protocols

import (
	"encoding"
	"fmt"

	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/tuneinsight/lattigo/v4/drlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

type LattigoShare interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

type LattigoKeygenProtocol interface {
	AllocateShare() Share
	AggregatedShares(dst Share, ss ...Share) error
	ReadCRP(crs drlwe.CRS) (CRP, error)
	GenShare(*rlwe.SecretKey, CRP, Share) error
	Finalize(CRP, ...Share) (interface{}, error)
}

type LattigoKeySwitchProtocol interface {
	AllocateShare() Share
	AggregatedShares(dst Share, ss ...Share) error
	GenShare(*rlwe.SecretKey, OutputKey, *rlwe.Ciphertext, Share) error
	Finalize(*rlwe.Ciphertext, *rlwe.Ciphertext, Share) error
}

type SKGProtocol struct {
	drlwe.Thresholdizer
}

func NewSKGProtocol(params rlwe.Parameters, arg map[string]interface{}) (*SKGProtocol, error) {
	return &SKGProtocol{Thresholdizer: *drlwe.NewThresholdizer(params)}, nil
}

func (skg *SKGProtocol) AllocateShare() Share {
	return Share{MHEShare: skg.AllocateThresholdSecretShare()}
}

func (skg *SKGProtocol) GenShamirPolynomial(threshold int, secret *rlwe.SecretKey) (*drlwe.ShamirPolynomial, error) {
	return skg.Thresholdizer.GenShamirPolynomial(threshold, secret)
}

func (skg *SKGProtocol) GenShareForParty(skp drlwe.ShamirPolynomial, receiver drlwe.ShamirPublicPoint, share Share) error {
	dstSkgShare, ok := share.MHEShare.(*drlwe.ShamirSecretShare)
	if !ok {
		return fmt.Errorf("invalid share type for argument dst: %T instead of %T", share, dstSkgShare)
	}
	skg.Thresholdizer.GenShamirSecretShare(receiver, &skp, dstSkgShare)
	return nil
}

func (skg *SKGProtocol) AggregatedShares(dst Share, ss ...Share) error {
	dstSkgShare, ok := dst.MHEShare.(*drlwe.ShamirSecretShare)
	if !ok {
		return fmt.Errorf("invalid share type for argument dst: %T instead of %T", dst, dstSkgShare)
	}

	skgShares := make([]*drlwe.ShamirSecretShare, 0, len(ss))
	for i, share := range ss {
		if skgShare, isSSS := share.MHEShare.(*drlwe.ShamirSecretShare); isSSS {
			skgShares = append(skgShares, skgShare)
		} else {
			return fmt.Errorf("invalid share type for argument %d: %T instead of %T", i, share, skgShare)
		}
	}

	for i := range skgShares {
		skg.Thresholdizer.AggregateShares(dstSkgShare, skgShares[i], dstSkgShare)
	}
	return nil
}

func (skg *SKGProtocol) Finalize(sess *pkg.Session, aggShare Share) error {
	return nil
}

type CKGProtocol struct {
	drlwe.CKGProtocol
	params *rlwe.Parameters
}

func NewCKGProtocol(params rlwe.Parameters, arg map[string]interface{}) (*CKGProtocol, error) {
	return &CKGProtocol{CKGProtocol: *drlwe.NewCKGProtocol(params), params: &params}, nil
}

func (ckg *CKGProtocol) AllocateShare() Share {
	return Share{MHEShare: ckg.CKGProtocol.AllocateShare()}
}

func (ckg *CKGProtocol) ReadCRP(crs drlwe.CRS) (CRP, error) {
	return ckg.CKGProtocol.SampleCRP(crs), nil
}

func (ckg *CKGProtocol) GenShare(sk *rlwe.SecretKey, crp CRP, share Share) error {
	ckgcrp, ok := crp.(drlwe.CKGCRP)
	if !ok {
		return fmt.Errorf("bad input type: %T", crp)
	}
	ckgShare, ok := share.MHEShare.(*drlwe.CKGShare)
	if !ok {
		return fmt.Errorf("bad share type: %T", share)
	}
	ckg.CKGProtocol.GenShare(sk, ckgcrp, ckgShare)
	return nil
}

func (ckg *CKGProtocol) AggregatedShares(dst Share, ss ...Share) error {

	dstCkgShare, ok := dst.MHEShare.(*drlwe.CKGShare)
	if !ok {
		return fmt.Errorf("invalid share type for argument dst: %T instead of %T", dst, dstCkgShare)
	}

	ckgShares := make([]*drlwe.CKGShare, 0, len(ss))
	for i, share := range ss {
		if ckgShare, isCKGShare := share.MHEShare.(*drlwe.CKGShare); isCKGShare {
			ckgShares = append(ckgShares, ckgShare)
		} else {
			return fmt.Errorf("invalid share type for argument %d: %T instead of %T", i, share, ckgShare)
		}
	}

	for i := range ckgShares {
		ckg.CKGProtocol.AggregateShares(dstCkgShare, ckgShares[i], dstCkgShare)
	}
	return nil
}

func (ckg *CKGProtocol) Finalize(crp CRP, aggShare ...Share) (interface{}, error) {
	ckgcrp, ok := crp.(drlwe.CKGCRP)
	if !ok {
		return nil, fmt.Errorf("bad input type: %T instead of %T", crp, drlwe.CKGCRP{})
	}
	if len(aggShare) != 1 {
		return nil, fmt.Errorf("bad aggregated share count: %d instead of %d", len(aggShare), 1)
	}
	ckgShare, ok := aggShare[0].MHEShare.(*drlwe.CKGShare)
	if !ok {
		return nil, fmt.Errorf("bad share type: %T instead of %T", aggShare[0].MHEShare, ckgShare)
	}

	pk := rlwe.NewPublicKey(*ckg.params)
	ckg.CKGProtocol.GenPublicKey(ckgShare, ckgcrp, pk)
	return pk, nil
}

type RTGProtocol struct {
	drlwe.RTGProtocol
	galEl  uint64 // TODO passed as argument ?
	params *rlwe.Parameters
}

func NewRTGProtocol(params rlwe.Parameters, args map[string]interface{}) (*RTGProtocol, error) {
	if _, hasArg := args["GalEl"]; !hasArg {
		return nil, fmt.Errorf("should provide argument: GalEl")
	}

	var galEl uint64
	switch ge := args["GalEl"].(type) {
	case uint64:
		galEl = ge
	case int:
		galEl = uint64(ge)
	case float64:
		galEl = uint64(ge)
	default:
		return nil, fmt.Errorf("invalid galois element type: %T instead of %T", args["GalEl"], galEl)
	}
	return &RTGProtocol{galEl: galEl, RTGProtocol: *drlwe.NewRTGProtocol(params), params: &params}, nil
}

func (rtg *RTGProtocol) AllocateShare() Share {
	return Share{MHEShare: rtg.RTGProtocol.AllocateShare()}
}

func (rtg *RTGProtocol) ReadCRP(crs drlwe.CRS) (CRP, error) {
	return rtg.RTGProtocol.SampleCRP(crs), nil
}

func (rtg *RTGProtocol) GenShare(sk *rlwe.SecretKey, crp CRP, share Share) error {
	rtgcrp, ok := crp.(drlwe.RTGCRP)
	if !ok {
		return fmt.Errorf("bad input type: %T", crp)
	}
	rtgShare, ok := share.MHEShare.(*drlwe.RTGShare)
	if !ok {
		return fmt.Errorf("bad share type: %T", share)
	}
	rtg.RTGProtocol.GenShare(sk, rtg.galEl, rtgcrp, rtgShare)
	return nil
}

func (rtg *RTGProtocol) AggregatedShares(dst Share, ss ...Share) error {
	dstRtgShare, ok := dst.MHEShare.(*drlwe.RTGShare)
	if !ok {
		return fmt.Errorf("invalid share type for argument dst: %T instead of %T", dst, dstRtgShare)
	}

	rtgShares := make([]*drlwe.RTGShare, 0, len(ss))
	for i, share := range ss {
		if rtgShare, isRTGShare := share.MHEShare.(*drlwe.RTGShare); isRTGShare {
			rtgShares = append(rtgShares, rtgShare)
		} else {
			return fmt.Errorf("invalid share type for argument %d: %T instead of %T", i, share, rtgShare)
		}
	}

	for i := range rtgShares {
		rtg.RTGProtocol.AggregateShares(dstRtgShare, rtgShares[i], dstRtgShare)
	}
	return nil
}

func (rtg *RTGProtocol) Finalize(crp CRP, aggShare ...Share) (swk interface{}, err error) {
	rtgcrp, ok := crp.(drlwe.RTGCRP)
	if !ok {
		return nil, fmt.Errorf("bad input type: %T instead of %T", crp, drlwe.RTGCRP{})
	}
	if len(aggShare) != 1 {
		return nil, fmt.Errorf("bad aggregated share count: %d instead of %d", len(aggShare), 1)
	}
	rtgShare, ok := aggShare[0].MHEShare.(*drlwe.RTGShare)
	if !ok {
		return nil, fmt.Errorf("bad share type: %T instead of %T", aggShare[0].MHEShare, rtgShare)
	}

	swk = rlwe.NewSwitchingKey(*rtg.params, rtg.params.QCount()-1, rtg.params.PCount()-1)
	rtg.GenRotationKey(rtgShare, rtgcrp, swk.(*rlwe.SwitchingKey))
	return swk, nil
}

type RKGProtocol struct {
	drlwe.RKGProtocol
	params *rlwe.Parameters
}

func NewRKGProtocol(params rlwe.Parameters, _ map[string]interface{}) (*RKGProtocol, error) {
	return &RKGProtocol{RKGProtocol: *drlwe.NewRKGProtocol(params), params: &params}, nil
}

func (rkg *RKGProtocol) AllocateShare() (ephSk *rlwe.SecretKey, r1Share, r2Share Share) {
	ephSk, s1, s2 := rkg.RKGProtocol.AllocateShare()
	return ephSk, Share{MHEShare: s1}, Share{MHEShare: s2}
}

func (rkg *RKGProtocol) AggregatedShares(dst Share, ss ...Share) error {
	dstRkgShare, ok := dst.MHEShare.(*drlwe.RKGShare)
	if !ok {
		return fmt.Errorf("invalid share type for argument dst: %T instead of %T", dst, dstRkgShare)
	}

	rkgShares := make([]*drlwe.RKGShare, 0, len(ss))
	for i, share := range ss {
		if rkgShare, isRKGShare := share.MHEShare.(*drlwe.RKGShare); isRKGShare {
			rkgShares = append(rkgShares, rkgShare)
		} else {
			return fmt.Errorf("invalid share type for argument %d: %T instead of %T", i, share.MHEShare, &drlwe.RKGShare{})
		}
	}

	for i := range rkgShares {
		rkg.RKGProtocol.AggregateShares(dstRkgShare, rkgShares[i], dstRkgShare)
	}
	return nil
}

func (rkg *RKGProtocol) ReadCRP(crs drlwe.CRS) (CRP, error) {
	return rkg.RKGProtocol.SampleCRP(crs), nil
}

func (rkg *RKGProtocol) GenShareRoundOne(sk *rlwe.SecretKey, crp CRP, ephSkOut *rlwe.SecretKey, share Share) error {
	rkgcrp, ok := crp.(drlwe.RKGCRP)
	if !ok {
		return fmt.Errorf("bad input type: %T instead of %T", crp, rkgcrp)
	}
	rkgShare, ok := share.MHEShare.(*drlwe.RKGShare)
	if !ok {
		return fmt.Errorf("invalid share type: %T instead of %T", share, rkgShare)
	}
	rkg.RKGProtocol.GenShareRoundOne(sk, rkgcrp, ephSkOut, rkgShare)
	return nil
}

func (rkg *RKGProtocol) GenShareRoundTwo(ephSk, sk *rlwe.SecretKey, aggRound1Share, share Share) error {
	rkgAggShareRound1, ok := aggRound1Share.MHEShare.(*drlwe.RKGShare)
	if !ok {
		return fmt.Errorf("invalid share type: %T instead of %T", aggRound1Share.MHEShare, rkgAggShareRound1)
	}
	rkgShare, ok := share.MHEShare.(*drlwe.RKGShare)
	if !ok {
		return fmt.Errorf("invalid share type: %T instead of %T", share.MHEShare, rkgShare)
	}
	rkg.RKGProtocol.GenShareRoundTwo(ephSk, sk, rkgAggShareRound1, rkgShare)
	return nil
}

func (rkg *RKGProtocol) Finalize(_ CRP, aggShares ...Share) (rlk interface{}, err error) {
	if len(aggShares) != 2 {
		return nil, fmt.Errorf("should have two aggregated shares, got %d", len(aggShares))
	}
	rkgAggShareRound1, ok := aggShares[0].MHEShare.(*drlwe.RKGShare)
	if !ok {
		return nil, fmt.Errorf("invalid round 1 share type: %T instead of %T", aggShares[0].MHEShare, rkgAggShareRound1)
	}
	rkgAggShareRound2, ok := aggShares[1].MHEShare.(*drlwe.RKGShare)
	if !ok {
		return nil, fmt.Errorf("invalid round 2 share type: %T instead of %T", aggShares[1].MHEShare, rkgAggShareRound2)
	}
	const maxRelinDegree = 2
	rlk = rlwe.NewRelinearizationKey(*rkg.params, maxRelinDegree)
	rkg.GenRelinearizationKey(rkgAggShareRound1, rkgAggShareRound2, rlk.(*rlwe.RelinearizationKey))
	return rlk, nil
}

type CKSProtocol struct {
	maxLevel int
	drlwe.CKSProtocol
}

func NewCKSProtocol(params rlwe.Parameters, args map[string]interface{}) (*CKSProtocol, error) {
	if _, hasArg := args["smudging"]; !hasArg {
		return nil, fmt.Errorf("should provide argument: smudging")
	}
	sigmaSmudging, isfloat64 := args["smudging"].(float64)
	if !isfloat64 {
		return nil, fmt.Errorf("invalid sigma smudging type: %T instead of %T", args["smudging"], sigmaSmudging)
	}
	return &CKSProtocol{maxLevel: params.MaxLevel(), CKSProtocol: *drlwe.NewCKSProtocol(params, sigmaSmudging)}, nil
}

func (cks *CKSProtocol) AllocateShare() Share {
	return Share{MHEShare: cks.CKSProtocol.AllocateShare(cks.maxLevel)}
}

func (cks *CKSProtocol) AggregatedShares(dst Share, ss ...Share) error {
	dstCksShare, ok := dst.MHEShare.(*drlwe.CKSShare)
	if !ok {
		return fmt.Errorf("invalid share type for argument dst: %T instead of %T", dst, dstCksShare)
	}

	cksShares := make([]*drlwe.CKSShare, 0, len(ss))
	for i, share := range ss {
		if cksShare, isCKSShare := share.MHEShare.(*drlwe.CKSShare); isCKSShare {
			cksShares = append(cksShares, cksShare)
		} else {
			return fmt.Errorf("invalid share type for argument %d: %T instead of %T", i, share.MHEShare, cksShare)
		}
	}

	for i := range cksShares {
		cks.CKSProtocol.AggregateShares(dstCksShare, cksShares[i], dstCksShare)
	}
	return nil
}

func (cks *CKSProtocol) GenShare(sk *rlwe.SecretKey, outKey OutputKey, in *rlwe.Ciphertext, share Share) error {
	skOut, ok := outKey.(*rlwe.SecretKey)
	if !ok {
		return fmt.Errorf("bad output key type: %T instead of %T", outKey, skOut)
	}

	cksShare, ok := share.MHEShare.(*drlwe.CKSShare)
	if !ok {
		return fmt.Errorf("bad share type: %T instead of %T", share.MHEShare, cksShare)
	}

	cks.CKSProtocol.GenShare(sk, skOut, in, cksShare)

	return nil
}

func (cks *CKSProtocol) Finalize(in, out *rlwe.Ciphertext, aggShare Share) error {
	cksAggShare, ok := aggShare.MHEShare.(*drlwe.CKSShare)
	if !ok {
		return fmt.Errorf("bad share type: %T instead of %T", aggShare.MHEShare, cksAggShare)
	}
	cks.KeySwitch(in, cksAggShare, out)
	return nil
}

type PCKSProtocol struct {
	maxLevel int
	drlwe.PCKSProtocol
}

func NewPCKSProtocol(params rlwe.Parameters, args map[string]interface{}) (*PCKSProtocol, error) {
	if _, hasArg := args["smudging"]; !hasArg {
		return nil, fmt.Errorf("should provide argument: smudging")
	}
	sigmaSmudging, isfloat64 := args["smudging"].(float64)
	if !isfloat64 {
		return nil, fmt.Errorf("invalid sigma smudging type: %T instead of %T", args["smudging"], sigmaSmudging)
	}
	return &PCKSProtocol{maxLevel: params.MaxLevel(), PCKSProtocol: *drlwe.NewPCKSProtocol(params, sigmaSmudging)}, nil
}

func (cks *PCKSProtocol) AllocateShare() Share {
	return Share{MHEShare: cks.PCKSProtocol.AllocateShare(cks.maxLevel)}
}

func (cks *PCKSProtocol) AggregatedShares(dst Share, ss ...Share) error {
	dstPcksShare, ok := dst.MHEShare.(*drlwe.PCKSShare)
	if !ok {
		return fmt.Errorf("invalid share type for argument dst: %T instead of %T", dst, dstPcksShare)
	}

	pcksShares := make([]*drlwe.PCKSShare, 0, len(ss))
	for i, share := range ss {
		if pcksShare, isPCKSShare := share.MHEShare.(*drlwe.PCKSShare); isPCKSShare {
			pcksShares = append(pcksShares, pcksShare)
		} else {
			return fmt.Errorf("invalid share type for argument %d: %T instead of %T", i, share.MHEShare, pcksShare)
		}
	}

	for i := range pcksShares {
		cks.PCKSProtocol.AggregateShares(dstPcksShare, pcksShares[i], dstPcksShare)
	}
	return nil
}

func (cks *PCKSProtocol) GenShare(sk *rlwe.SecretKey, outKey OutputKey, in *rlwe.Ciphertext, share Share) error {
	pkOut, ok := outKey.(*rlwe.PublicKey)
	if !ok {
		return fmt.Errorf("bad output key type: %T instead of %T", outKey, pkOut)
	}

	pcksShare, ok := share.MHEShare.(*drlwe.PCKSShare)
	if !ok {
		return fmt.Errorf("bad share type: %T instead of %T", share.MHEShare, pcksShare)
	}

	cks.PCKSProtocol.GenShare(sk, pkOut, in, pcksShare)

	return nil
}

func (cks *PCKSProtocol) Finalize(in, out *rlwe.Ciphertext, aggShare Share) error {
	pcksAggShare, ok := aggShare.MHEShare.(*drlwe.PCKSShare)
	if !ok {
		return fmt.Errorf("bad share type: %T instead of %T", aggShare.MHEShare, pcksAggShare)
	}
	cks.PCKSProtocol.KeySwitch(in, pcksAggShare, out)
	return nil
}
