package protocols

import (
	"encoding"
	"fmt"
	"strconv"

	"github.com/ldsec/helium/pkg/pkg"
	"github.com/tuneinsight/lattigo/v4/drlwe"
	"github.com/tuneinsight/lattigo/v4/ring"
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
	return &SKGProtocol{Thresholdizer: drlwe.NewThresholdizer(params)}, nil
}

func (skg *SKGProtocol) AllocateShare() Share {
	s := skg.AllocateThresholdSecretShare()
	return Share{MHEShare: &s}
}

func (skg *SKGProtocol) GenShamirPolynomial(threshold int, secret *rlwe.SecretKey) (drlwe.ShamirPolynomial, error) {
	return skg.Thresholdizer.GenShamirPolynomial(threshold, secret)
}

func (skg *SKGProtocol) GenShareForParty(skp drlwe.ShamirPolynomial, receiver drlwe.ShamirPublicPoint, share Share) error {
	dstSkgShare, ok := share.MHEShare.(*drlwe.ShamirSecretShare)
	if !ok {
		return fmt.Errorf("invalid share type for argument dst: %T instead of %T", share, dstSkgShare)
	}
	skg.Thresholdizer.GenShamirSecretShare(receiver, skp, dstSkgShare)
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
		skg.Thresholdizer.AggregateShares(*dstSkgShare, *skgShares[i], dstSkgShare)
	}
	return nil
}

func (skg *SKGProtocol) Finalize(sess *pkg.Session, aggShare Share) error {
	return nil
}

type CKGProtocol struct {
	drlwe.PublicKeyGenProtocol
	params *rlwe.Parameters
}

func NewCKGProtocol(params rlwe.Parameters, arg map[string]string) (*CKGProtocol, error) {
	return &CKGProtocol{PublicKeyGenProtocol: drlwe.NewPublicKeyGenProtocol(params), params: &params}, nil
}

func (ckg *CKGProtocol) AllocateShare() Share {
	s := ckg.PublicKeyGenProtocol.AllocateShare()
	return Share{MHEShare: &s}
}

func (ckg *CKGProtocol) ReadCRP(crs drlwe.CRS) (CRP, error) {
	return ckg.PublicKeyGenProtocol.SampleCRP(crs), nil
}

func (ckg *CKGProtocol) GenShare(sk *rlwe.SecretKey, crp CRP, share Share) error {
	ckgcrp, ok := crp.(drlwe.PublicKeyGenCRP)
	if !ok {
		return fmt.Errorf("bad input type: %T", crp)
	}
	ckgShare, ok := share.MHEShare.(*drlwe.PublicKeyGenShare)
	if !ok {
		return fmt.Errorf("bad share type: %T", share)
	}
	ckg.PublicKeyGenProtocol.GenShare(sk, ckgcrp, ckgShare)
	return nil
}

func (ckg *CKGProtocol) AggregatedShares(dst Share, ss ...Share) error {

	dstCkgShare, ok := dst.MHEShare.(*drlwe.PublicKeyGenShare)
	if !ok {
		return fmt.Errorf("invalid share type for argument dst: %T instead of %T", dst, dstCkgShare)
	}

	ckgShares := make([]*drlwe.PublicKeyGenShare, 0, len(ss))
	for i, share := range ss {
		if ckgShare, isCKGShare := share.MHEShare.(*drlwe.PublicKeyGenShare); isCKGShare {
			ckgShares = append(ckgShares, ckgShare)
		} else {
			return fmt.Errorf("invalid share type for argument %d: %T instead of %T", i, share, ckgShare)
		}
	}

	for i := range ckgShares {
		ckg.PublicKeyGenProtocol.AggregateShares(*dstCkgShare, *ckgShares[i], dstCkgShare)
	}
	return nil
}

func (ckg *CKGProtocol) Finalize(crp CRP, aggShare ...Share) (interface{}, error) {
	ckgcrp, ok := crp.(drlwe.PublicKeyGenCRP)
	if !ok {
		return nil, fmt.Errorf("bad input type: %T instead of %T", crp, drlwe.PublicKeyGenCRP{})
	}
	if len(aggShare) != 1 {
		return nil, fmt.Errorf("bad aggregated share count: %d instead of %d", len(aggShare), 1)
	}
	ckgShare, ok := aggShare[0].MHEShare.(*drlwe.PublicKeyGenShare)
	if !ok {
		return nil, fmt.Errorf("bad share type: %T instead of %T", aggShare[0].MHEShare, ckgShare)
	}

	pk := rlwe.NewPublicKey(*ckg.params)
	ckg.PublicKeyGenProtocol.GenPublicKey(*ckgShare, ckgcrp, pk)
	return pk, nil
}

type RTGProtocol struct {
	drlwe.GaloisKeyGenProtocol
	galEl  uint64 // TODO passed as argument ?
	params *rlwe.Parameters
}

func NewRTGProtocol(params rlwe.Parameters, args map[string]string) (*RTGProtocol, error) {
	if _, hasArg := args["GalEl"]; !hasArg {
		return nil, fmt.Errorf("should provide argument: GalEl")
	}

	galEl, err := strconv.ParseUint(args["GalEl"], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid galois element type: %T instead of %T", args["GalEl"], galEl)
	}

	return &RTGProtocol{galEl: galEl, GaloisKeyGenProtocol: drlwe.NewGaloisKeyGenProtocol(params), params: &params}, nil
}

func (rtg *RTGProtocol) AllocateShare() Share {
	s := rtg.GaloisKeyGenProtocol.AllocateShare()
	return Share{MHEShare: &s}
}

func (rtg *RTGProtocol) ReadCRP(crs drlwe.CRS) (CRP, error) {
	return rtg.GaloisKeyGenProtocol.SampleCRP(crs), nil
}

func (rtg *RTGProtocol) GenShare(sk *rlwe.SecretKey, crp CRP, share Share) error {
	rtgcrp, ok := crp.(drlwe.GaloisKeyGenCRP)
	if !ok {
		return fmt.Errorf("bad input type: %T", crp)
	}
	rtgShare, ok := share.MHEShare.(*drlwe.GaloisKeyGenShare)
	if !ok {
		return fmt.Errorf("bad share type: %T", share)
	}
	rtg.GaloisKeyGenProtocol.GenShare(sk, rtg.galEl, rtgcrp, rtgShare)
	return nil
}

func (rtg *RTGProtocol) AggregatedShares(dst Share, ss ...Share) error {
	dstRtgShare, ok := dst.MHEShare.(*drlwe.GaloisKeyGenShare)
	if !ok {
		return fmt.Errorf("invalid share type for argument dst: %T instead of %T", dst, dstRtgShare)
	}

	rtgShares := make([]*drlwe.GaloisKeyGenShare, 0, len(ss))
	for i, share := range ss {
		if rtgShare, isRTGShare := share.MHEShare.(*drlwe.GaloisKeyGenShare); isRTGShare {
			rtgShares = append(rtgShares, rtgShare)
		} else {
			return fmt.Errorf("invalid share type for argument %d: %T instead of %T", i, share, rtgShare)
		}
	}

	dstRtgShare.GaloisElement = rtg.galEl
	for i := range rtgShares {
		rtg.GaloisKeyGenProtocol.AggregateShares(*dstRtgShare, *rtgShares[i], dstRtgShare)
	}
	return nil
}

func (rtg *RTGProtocol) Finalize(crp CRP, aggShare ...Share) (swk interface{}, err error) {
	rtgcrp, ok := crp.(drlwe.GaloisKeyGenCRP)
	if !ok {
		return nil, fmt.Errorf("bad input type: %T instead of %T", crp, drlwe.GaloisKeyGenCRP{})
	}
	if len(aggShare) != 1 {
		return nil, fmt.Errorf("bad aggregated share count: %d instead of %d", len(aggShare), 1)
	}
	rtgShare, ok := aggShare[0].MHEShare.(*drlwe.GaloisKeyGenShare)
	if !ok {
		return nil, fmt.Errorf("bad share type: %T instead of %T", aggShare[0].MHEShare, rtgShare)
	}

	swk = rlwe.NewGaloisKey(*rtg.params)
	err = rtg.GaloisKeyGenProtocol.GenGaloisKey(*rtgShare, rtgcrp, swk.(*rlwe.GaloisKey))
	return swk, err
}

type RKGProtocol struct {
	drlwe.RelinearizationKeyGenProtocol
	params *rlwe.Parameters

	round uint64
	ephSk *rlwe.SecretKey
}

func NewRKGProtocol(params rlwe.Parameters, ephSk *rlwe.SecretKey, round uint64, _ map[string]string) (*RKGProtocol, error) {
	return &RKGProtocol{RelinearizationKeyGenProtocol: drlwe.NewRelinearizationKeyGenProtocol(params), params: &params, round: round, ephSk: ephSk}, nil
}

func (rkg *RKGProtocol) AllocateShare() (share Share) {
	_, s1, _ := rkg.RelinearizationKeyGenProtocol.AllocateShare()
	return Share{MHEShare: &s1}
}

func (rkg *RKGProtocol) AggregatedShares(dst Share, ss ...Share) error {
	dstRkgShare, ok := dst.MHEShare.(*drlwe.RelinearizationKeyGenShare)
	if !ok {
		return fmt.Errorf("invalid share type for argument dst: %T instead of %T", dst, dstRkgShare)
	}

	rkgShares := make([]*drlwe.RelinearizationKeyGenShare, 0, len(ss))
	for i, share := range ss {
		if rkgShare, isRKGShare := share.MHEShare.(*drlwe.RelinearizationKeyGenShare); isRKGShare {
			rkgShares = append(rkgShares, rkgShare)
		} else {
			return fmt.Errorf("invalid share type for argument %d: %T instead of %T", i, share.MHEShare, &drlwe.RelinearizationKeyGenShare{})
		}
	}

	for i := range rkgShares {
		rkg.RelinearizationKeyGenProtocol.AggregateShares(*dstRkgShare, *rkgShares[i], dstRkgShare)
	}
	return nil
}

func (rkg *RKGProtocol) ReadCRP(crs drlwe.CRS) (CRP, error) {
	return rkg.RelinearizationKeyGenProtocol.SampleCRP(crs), nil
}

func (rkg *RKGProtocol) GenShare(sk *rlwe.SecretKey, crp CRP, share Share) error {
	rkgShare, ok := share.MHEShare.(*drlwe.RelinearizationKeyGenShare)
	if !ok {
		return fmt.Errorf("invalid share type: %T instead of %T", share, rkgShare)
	}
	if rkg.round == 1 {
		rkgcrp, ok := crp.(drlwe.RelinearizationKeyGenCRP)
		if !ok {
			return fmt.Errorf("bad input type: %T instead of %T", crp, rkgcrp)
		}
		rkg.RelinearizationKeyGenProtocol.GenShareRoundOne(sk, rkgcrp, rkg.ephSk, rkgShare)
	} else {
		rkgShareRoundOne, ok := crp.(*drlwe.RelinearizationKeyGenShare)
		if !ok {
			return fmt.Errorf("bad input type: %T instead of %T", crp, rkgShareRoundOne)
		}
		rkg.RelinearizationKeyGenProtocol.GenShareRoundTwo(rkg.ephSk, sk, *rkgShareRoundOne, rkgShare)
	}

	return nil
}

func (rkg *RKGProtocol) Finalize(round1 CRP, aggShares ...Share) (rlk interface{}, err error) {
	if len(aggShares) != 1 {
		return nil, fmt.Errorf("should have two aggregated shares, got %d", len(aggShares))
	}
	rkgAggShareRound1, ok := round1.(*drlwe.RelinearizationKeyGenShare)
	if !ok {
		return nil, fmt.Errorf("invalid round 1 share type: %T instead of %T", round1, rkgAggShareRound1)
	}
	rkgAggShareRound2, ok := aggShares[0].MHEShare.(*drlwe.RelinearizationKeyGenShare)
	if !ok {
		return nil, fmt.Errorf("invalid round 2 share type: %T instead of %T", aggShares[0].MHEShare, rkgAggShareRound2)
	}
	const maxRelinDegree = 2
	rlk = rlwe.NewRelinearizationKey(*rkg.params)
	rkg.RelinearizationKeyGenProtocol.GenRelinearizationKey(*rkgAggShareRound1, *rkgAggShareRound2, rlk.(*rlwe.RelinearizationKey))
	return rlk, nil
}

type CKSProtocol struct {
	maxLevel int
	drlwe.KeySwitchProtocol
}

func NewCKSProtocol(params rlwe.Parameters, args map[string]string) (*CKSProtocol, error) {
	if _, hasArg := args["smudging"]; !hasArg {
		return nil, fmt.Errorf("should provide argument: smudging")
	}

	sigmaSmudging, err := strconv.ParseFloat(args["smudging"], 64)
	if err != nil {
		return nil, fmt.Errorf("sigma smudging: %s cannot be parsed to %T", args["smudging"], sigmaSmudging)
	}
	p, err := drlwe.NewKeySwitchProtocol(params, ring.DiscreteGaussian{Sigma: sigmaSmudging, Bound: 6 * sigmaSmudging})
	if err != nil {
		return nil, err
	}
	return &CKSProtocol{maxLevel: params.MaxLevel(), KeySwitchProtocol: p}, nil
}

func (cks *CKSProtocol) AllocateShare() Share {
	s := cks.KeySwitchProtocol.AllocateShare(cks.maxLevel)
	return Share{MHEShare: &s}
}

func (cks *CKSProtocol) AggregatedShares(dst Share, ss ...Share) error {
	dstCksShare, ok := dst.MHEShare.(*drlwe.KeySwitchShare)
	if !ok {
		return fmt.Errorf("invalid share type for argument dst: %T instead of %T", dst, dstCksShare)
	}

	cksShares := make([]*drlwe.KeySwitchShare, 0, len(ss))
	for i, share := range ss {
		if cksShare, isCKSShare := share.MHEShare.(*drlwe.KeySwitchShare); isCKSShare {
			cksShares = append(cksShares, cksShare)
		} else {
			return fmt.Errorf("invalid share type for argument %d: %T instead of %T", i, share.MHEShare, cksShare)
		}
	}

	for i := range cksShares {
		cks.KeySwitchProtocol.AggregateShares(*dstCksShare, *cksShares[i], dstCksShare)
	}
	return nil
}

func (cks *CKSProtocol) GenShare(sk *rlwe.SecretKey, outKey OutputKey, in *rlwe.Ciphertext, share Share) error {
	skOut, ok := outKey.(*rlwe.SecretKey)
	if !ok {
		return fmt.Errorf("bad output key type: %T instead of %T", outKey, skOut)
	}

	cksShare, ok := share.MHEShare.(*drlwe.KeySwitchShare)
	if !ok {
		return fmt.Errorf("bad share type: %T instead of %T", share.MHEShare, cksShare)
	}

	cks.KeySwitchProtocol.GenShare(sk, skOut, in, cksShare)

	return nil
}

func (cks *CKSProtocol) Finalize(in, out *rlwe.Ciphertext, aggShare Share) error {
	cksAggShare, ok := aggShare.MHEShare.(*drlwe.KeySwitchShare)
	if !ok {
		return fmt.Errorf("bad share type: %T instead of %T", aggShare.MHEShare, cksAggShare)
	}
	cks.KeySwitchProtocol.KeySwitch(in, *cksAggShare, out)
	return nil
}

type PCKSProtocol struct {
	maxLevel int
	drlwe.PublicKeySwitchProtocol
}

func NewPCKSProtocol(params rlwe.Parameters, args map[string]string) (*PCKSProtocol, error) {
	if _, hasArg := args["smudging"]; !hasArg {
		return nil, fmt.Errorf("should provide argument: smudging")
	}
	sigmaSmudging, err := strconv.ParseFloat(args["smudging"], 64)
	if err != nil {
		return nil, fmt.Errorf("sigma smudging: %s cannot be parsed to %T", args["smudging"], sigmaSmudging)
	}
	p, err := drlwe.NewPublicKeySwitchProtocol(params, ring.DiscreteGaussian{Sigma: sigmaSmudging, Bound: 6 * sigmaSmudging})
	if err != nil {
		return nil, err
	}
	return &PCKSProtocol{maxLevel: params.MaxLevel(), PublicKeySwitchProtocol: p}, nil
}

func (cks *PCKSProtocol) AllocateShare() Share {
	s := cks.PublicKeySwitchProtocol.AllocateShare(cks.maxLevel)
	return Share{MHEShare: &s}
}

func (cks *PCKSProtocol) AggregatedShares(dst Share, ss ...Share) error {
	dstPcksShare, ok := dst.MHEShare.(*drlwe.PublicKeySwitchShare)
	if !ok {
		return fmt.Errorf("invalid share type for argument dst: %T instead of %T", dst, dstPcksShare)
	}

	pcksShares := make([]*drlwe.PublicKeySwitchShare, 0, len(ss))
	for i, share := range ss {
		if pcksShare, isPCKSShare := share.MHEShare.(*drlwe.PublicKeySwitchShare); isPCKSShare {
			pcksShares = append(pcksShares, pcksShare)
		} else {
			return fmt.Errorf("invalid share type for argument %d: %T instead of %T", i, share.MHEShare, pcksShare)
		}
	}

	for i := range pcksShares {
		cks.PublicKeySwitchProtocol.AggregateShares(*dstPcksShare, *pcksShares[i], dstPcksShare)
	}
	return nil
}

func (cks *PCKSProtocol) GenShare(sk *rlwe.SecretKey, outKey OutputKey, in *rlwe.Ciphertext, share Share) error {
	pkOut, ok := outKey.(*rlwe.PublicKey)
	if !ok {
		return fmt.Errorf("bad output key type: %T instead of %T", outKey, pkOut)
	}

	pcksShare, ok := share.MHEShare.(*drlwe.PublicKeySwitchShare)
	if !ok {
		return fmt.Errorf("bad share type: %T instead of %T", share.MHEShare, pcksShare)
	}

	cks.PublicKeySwitchProtocol.GenShare(sk, pkOut, in, pcksShare)

	return nil
}

func (cks *PCKSProtocol) Finalize(in, out *rlwe.Ciphertext, aggShare Share) error {
	pcksAggShare, ok := aggShare.MHEShare.(*drlwe.PublicKeySwitchShare)
	if !ok {
		return fmt.Errorf("bad share type: %T instead of %T", aggShare.MHEShare, pcksAggShare)
	}
	cks.PublicKeySwitchProtocol.KeySwitch(in, *pcksAggShare, out)
	return nil
}
