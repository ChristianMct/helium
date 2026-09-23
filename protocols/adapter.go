package protocols

import (
	"encoding"
	"fmt"
	"strconv"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	mhe "github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
)

// The types and function in this file are a wrapper around the lattigo library.
// The goal of this wrapper is to provide a common interface for all MHE protocols.

// mheProtocol is a common interface for all MHE protocols
// implemented in Lattigo.
type mheProtocol interface {
	AllocateShare() Share
	ReadCRP(crs mhe.CRS) (CRP, error)
	GenShare(*rlwe.SecretKey, Input, Share) error
	AggregatedShares(dst Share, ss ...Share) error
	Finalize(in Input, agg Share, outRec interface{}) error
}

// LattigoShare is a common interface for all Lattigo shares
type LattigoShare interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

func newMHEProtocol(sig Signature, params rlwe.Parameters) (mheProtocol, error) {
	switch sig.Type {
	case CKG:
		return NewCKGProtocol(params, sig.Args)
	case RTG:
		return NewRTGProtocol(params, sig.Args)
	case RKG1:
		return NewRKGProtocol(params, nil, 1, sig.Args)
	case RKG:
		return NewRKGProtocol(params, nil, 2, sig.Args)
	case CKS:
		return NewCKSProtocol(params, sig.Args)
	case DEC:
		return NewCKSProtocol(params, sig.Args)
	case PCKS:
		return NewPCKSProtocol(params, sig.Args)
	default:
		return nil, fmt.Errorf("unsupported MHE protocol type: %s", sig.Type)
	}
}

type SKGProtocol struct {
	mhe.Thresholdizer
}

type CKGProtocol struct {
	mhe.PublicKeyGenProtocol
	params *rlwe.Parameters
}

func NewCKGProtocol(params rlwe.Parameters, arg map[string]string) (*CKGProtocol, error) {
	return &CKGProtocol{PublicKeyGenProtocol: mhe.NewPublicKeyGenProtocol(params), params: &params}, nil
}

func (ckg *CKGProtocol) AllocateShare() Share {
	s := ckg.PublicKeyGenProtocol.AllocateShare()
	return Share{MHEShare: &s}
}

func (ckg *CKGProtocol) ReadCRP(crs mhe.CRS) (CRP, error) {
	return ckg.PublicKeyGenProtocol.SampleCRP(crs), nil
}

func (ckg *CKGProtocol) GenShare(sk *rlwe.SecretKey, crp Input, share Share) error {
	ckgcrp, ok := crp.(mhe.PublicKeyGenCRP)
	if !ok {
		return fmt.Errorf("bad input type: %T instead of %T", crp, ckgcrp)
	}
	ckgShare, ok := share.MHEShare.(*mhe.PublicKeyGenShare)
	if !ok {
		return fmt.Errorf("bad share type: %T instead of %T", share, ckgShare)
	}
	ckg.PublicKeyGenProtocol.GenShare(sk, ckgcrp, ckgShare)
	return nil
}

func (ckg *CKGProtocol) AggregatedShares(dst Share, ss ...Share) error {

	dstCkgShare, ok := dst.MHEShare.(*mhe.PublicKeyGenShare)
	if !ok {
		return fmt.Errorf("invalid share type for argument dst: %T instead of %T", dst, dstCkgShare)
	}

	ckgShares := make([]*mhe.PublicKeyGenShare, 0, len(ss))
	for i, share := range ss {
		if ckgShare, isCKGShare := share.MHEShare.(*mhe.PublicKeyGenShare); isCKGShare {
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

func (ckg *CKGProtocol) Finalize(crp Input, aggShare Share, rec interface{}) error {
	ckgcrp, ok := crp.(mhe.PublicKeyGenCRP)
	if !ok {
		return fmt.Errorf("bad input type: %T instead of %T", crp, mhe.PublicKeyGenCRP{})
	}

	ckgShare, ok := aggShare.MHEShare.(*mhe.PublicKeyGenShare)
	if !ok {
		return fmt.Errorf("bad share type: %T instead of %T", aggShare.MHEShare, ckgShare)
	}

	recPk, ok := rec.(*rlwe.PublicKey)
	if !ok {
		return fmt.Errorf("bad receiver type: %T instead of %T", rec, recPk)
	}

	ckg.PublicKeyGenProtocol.GenPublicKey(*ckgShare, ckgcrp, recPk)
	return nil
}

type RTGProtocol struct {
	mhe.GaloisKeyGenProtocol
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

	return &RTGProtocol{galEl: galEl, GaloisKeyGenProtocol: mhe.NewGaloisKeyGenProtocol(params), params: &params}, nil
}

func (rtg *RTGProtocol) AllocateShare() Share {
	s := rtg.GaloisKeyGenProtocol.AllocateShare()
	return Share{MHEShare: &s}
}

func (rtg *RTGProtocol) ReadCRP(crs mhe.CRS) (CRP, error) {
	return rtg.GaloisKeyGenProtocol.SampleCRP(crs), nil
}

func (rtg *RTGProtocol) GenShare(sk *rlwe.SecretKey, crp Input, share Share) error {
	rtgcrp, ok := crp.(mhe.GaloisKeyGenCRP)
	if !ok {
		return fmt.Errorf("bad input type: %T", crp)
	}
	rtgShare, ok := share.MHEShare.(*mhe.GaloisKeyGenShare)
	if !ok {
		return fmt.Errorf("bad share type: %T", share)
	}
	rtg.GaloisKeyGenProtocol.GenShare(sk, rtg.galEl, rtgcrp, rtgShare)
	return nil
}

func (rtg *RTGProtocol) AggregatedShares(dst Share, ss ...Share) error {
	dstRtgShare, ok := dst.MHEShare.(*mhe.GaloisKeyGenShare)
	if !ok {
		return fmt.Errorf("invalid share type for argument dst: %T instead of %T", dst, dstRtgShare)
	}

	rtgShares := make([]*mhe.GaloisKeyGenShare, 0, len(ss))
	for i, share := range ss {
		if rtgShare, isRTGShare := share.MHEShare.(*mhe.GaloisKeyGenShare); isRTGShare {
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

func (rtg *RTGProtocol) Finalize(crp Input, aggShare Share, rec interface{}) error {
	rtgcrp, ok := crp.(mhe.GaloisKeyGenCRP)
	if !ok {
		return fmt.Errorf("bad input type: %T instead of %T", crp, rtgcrp)
	}

	rtgShare, ok := aggShare.MHEShare.(*mhe.GaloisKeyGenShare)
	if !ok {
		return fmt.Errorf("bad share type: %T instead of %T", aggShare.MHEShare, rtgShare)
	}

	recRtk, ok := rec.(*rlwe.GaloisKey)
	if !ok {
		return fmt.Errorf("bad receiver type: %T instead of %T", rec, recRtk)
	}

	return rtg.GaloisKeyGenProtocol.GenGaloisKey(*rtgShare, rtgcrp, recRtk)
}

type RKGProtocol struct {
	mhe.RelinearizationKeyGenProtocol
	params *rlwe.Parameters

	round uint64
	ephSk *rlwe.SecretKey
}

func NewRKGProtocol(params rlwe.Parameters, ephSk *rlwe.SecretKey, round uint64, _ map[string]string) (*RKGProtocol, error) {
	return &RKGProtocol{RelinearizationKeyGenProtocol: mhe.NewRelinearizationKeyGenProtocol(params), params: &params, round: round, ephSk: ephSk}, nil
}

func (rkg *RKGProtocol) AllocateShare() (share Share) {
	_, s1, _ := rkg.RelinearizationKeyGenProtocol.AllocateShare()
	return Share{MHEShare: &s1}
}

func (rkg *RKGProtocol) AggregatedShares(dst Share, ss ...Share) error {
	dstRkgShare, ok := dst.MHEShare.(*mhe.RelinearizationKeyGenShare)
	if !ok {
		return fmt.Errorf("invalid share type for argument dst: %T instead of %T", dst, dstRkgShare)
	}

	rkgShares := make([]*mhe.RelinearizationKeyGenShare, 0, len(ss))
	for i, share := range ss {
		if rkgShare, isRKGShare := share.MHEShare.(*mhe.RelinearizationKeyGenShare); isRKGShare {
			rkgShares = append(rkgShares, rkgShare)
		} else {
			return fmt.Errorf("invalid share type for argument %d: %T instead of %T", i, share.MHEShare, &mhe.RelinearizationKeyGenShare{})
		}
	}

	for i := range rkgShares {
		rkg.RelinearizationKeyGenProtocol.AggregateShares(*dstRkgShare, *rkgShares[i], dstRkgShare)
	}
	return nil
}

func (rkg *RKGProtocol) ReadCRP(crs mhe.CRS) (CRP, error) {
	return rkg.RelinearizationKeyGenProtocol.SampleCRP(crs), nil
}

func (rkg *RKGProtocol) GenShare(sk *rlwe.SecretKey, input Input, share Share) error {
	rkgShare, ok := share.MHEShare.(*mhe.RelinearizationKeyGenShare)
	if !ok {
		return fmt.Errorf("invalid share type: %T instead of %T", share, rkgShare)
	}
	if rkg.round == 1 {
		rkgcrp, ok := input.(mhe.RelinearizationKeyGenCRP)
		if !ok {
			return fmt.Errorf("bad input type: %T instead of %T", input, rkgcrp)
		}
		rkg.RelinearizationKeyGenProtocol.GenShareRoundOne(sk, rkgcrp, rkg.ephSk, rkgShare)
	} else {
		rkgShareRoundOne, ok := input.(*mhe.RelinearizationKeyGenShare)
		if !ok {
			return fmt.Errorf("bad input type: %T instead of %T", input, rkgShareRoundOne)
		}
		rkg.RelinearizationKeyGenProtocol.GenShareRoundTwo(rkg.ephSk, sk, *rkgShareRoundOne, rkgShare)
	}

	return nil
}

func (rkg *RKGProtocol) Finalize(round1 Input, aggShares Share, rec interface{}) error {

	rkgAggShareRound1, ok := round1.(*mhe.RelinearizationKeyGenShare)
	if !ok {
		return fmt.Errorf("invalid input type: %T instead of %T", round1, rkgAggShareRound1)
	}

	rkgAggShareRound2, ok := aggShares.MHEShare.(*mhe.RelinearizationKeyGenShare)
	if !ok {
		return fmt.Errorf("invalid share type: %T instead of %T", aggShares.MHEShare, rkgAggShareRound2)
	}

	rlkRec, ok := rec.(*rlwe.RelinearizationKey)
	if !ok {
		return fmt.Errorf("invalid receiver type: %T instead of %T", rec, rlkRec)
	}

	rkg.RelinearizationKeyGenProtocol.GenRelinearizationKey(*rkgAggShareRound1, *rkgAggShareRound2, rlkRec)
	return nil
}

type CKSProtocol struct {
	maxLevel int
	mhe.KeySwitchProtocol
}

func NewCKSProtocol(params rlwe.Parameters, args map[string]string) (*CKSProtocol, error) {
	if _, hasArg := args["smudging"]; !hasArg {
		return nil, fmt.Errorf("should provide argument: smudging")
	}

	sigmaSmudging, err := strconv.ParseFloat(args["smudging"], 64)
	if err != nil {
		return nil, fmt.Errorf("sigma smudging: %s cannot be parsed to %T", args["smudging"], sigmaSmudging)
	}
	p, err := mhe.NewKeySwitchProtocol(params, ring.DiscreteGaussian{Sigma: sigmaSmudging, Bound: 6 * sigmaSmudging})
	if err != nil {
		return nil, err
	}
	return &CKSProtocol{maxLevel: params.MaxLevel(), KeySwitchProtocol: p}, nil
}

func (cks *CKSProtocol) AllocateShare() Share {
	s := cks.KeySwitchProtocol.AllocateShare(cks.maxLevel)
	return Share{MHEShare: &s}
}

func (cks *CKSProtocol) ReadCRP(crs mhe.CRS) (CRP, error) {
	panic("CKS protocol does not require a CRP")
}

func (cks *CKSProtocol) AggregatedShares(dst Share, ss ...Share) error {
	dstCksShare, ok := dst.MHEShare.(*mhe.KeySwitchShare)
	if !ok {
		return fmt.Errorf("invalid share type for argument dst: %T instead of %T", dst, dstCksShare)
	}

	cksShares := make([]*mhe.KeySwitchShare, 0, len(ss))
	for i, share := range ss {
		if cksShare, isCKSShare := share.MHEShare.(*mhe.KeySwitchShare); isCKSShare {
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

func (cks *CKSProtocol) GenShare(sk *rlwe.SecretKey, in Input, share Share) error {

	ksin, ok := in.(*KeySwitchInput)
	if !ok {
		return fmt.Errorf("bad input type: %T instead of %T", in, ksin)
	}

	skOut, ok := ksin.OutputKey.(*rlwe.SecretKey)
	if !ok {
		return fmt.Errorf("bad output key type: %T instead of %T", ksin.OutputKey, skOut)
	}

	if ksin.InpuCt == nil {
		return fmt.Errorf("input ciphertext is nil")
	}

	cksShare, ok := share.MHEShare.(*mhe.KeySwitchShare)
	if !ok {
		return fmt.Errorf("bad share type: %T instead of %T", share.MHEShare, cksShare)
	}

	cks.KeySwitchProtocol.GenShare(sk, skOut, ksin.InpuCt, cksShare)

	return nil
}

func (cks *CKSProtocol) Finalize(in Input, aggShare Share, rec interface{}) error {

	ksin, ok := in.(*KeySwitchInput)
	if !ok {
		return fmt.Errorf("bad input type: %T instead of %T", in, ksin)
	}

	if ksin.InpuCt == nil {
		return fmt.Errorf("input ciphertext is nil")
	}

	cksAggShare, ok := aggShare.MHEShare.(*mhe.KeySwitchShare)
	if !ok {
		return fmt.Errorf("bad share type: %T instead of %T", aggShare.MHEShare, cksAggShare)
	}

	outCt, ok := rec.(*rlwe.Ciphertext)
	if !ok {
		return fmt.Errorf("bad receiver type: %T instead of %T", rec, outCt)
	}

	cks.KeySwitchProtocol.KeySwitch(ksin.InpuCt, *cksAggShare, outCt)
	return nil
}

type PCKSProtocol struct {
	maxLevel int
	mhe.PublicKeySwitchProtocol
}

func NewPCKSProtocol(params rlwe.Parameters, args map[string]string) (*PCKSProtocol, error) {
	if _, hasArg := args["smudging"]; !hasArg {
		return nil, fmt.Errorf("should provide argument: smudging")
	}
	sigmaSmudging, err := strconv.ParseFloat(args["smudging"], 64)
	if err != nil {
		return nil, fmt.Errorf("sigma smudging: %s cannot be parsed to %T", args["smudging"], sigmaSmudging)
	}
	p, err := mhe.NewPublicKeySwitchProtocol(params, ring.DiscreteGaussian{Sigma: sigmaSmudging, Bound: 6 * sigmaSmudging})
	if err != nil {
		return nil, err
	}
	return &PCKSProtocol{maxLevel: params.MaxLevel(), PublicKeySwitchProtocol: p}, nil
}

func (cks *PCKSProtocol) AllocateShare() Share {
	s := cks.PublicKeySwitchProtocol.AllocateShare(cks.maxLevel)
	return Share{MHEShare: &s}
}

func (cks *PCKSProtocol) ReadCRP(crs mhe.CRS) (CRP, error) {
	panic("PCKS protocol does not require a CRP")
}

func (cks *PCKSProtocol) AggregatedShares(dst Share, ss ...Share) error {
	dstPcksShare, ok := dst.MHEShare.(*mhe.PublicKeySwitchShare)
	if !ok {
		return fmt.Errorf("invalid share type for argument dst: %T instead of %T", dst, dstPcksShare)
	}

	pcksShares := make([]*mhe.PublicKeySwitchShare, 0, len(ss))
	for i, share := range ss {
		if pcksShare, isPCKSShare := share.MHEShare.(*mhe.PublicKeySwitchShare); isPCKSShare {
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

func (cks *PCKSProtocol) GenShare(sk *rlwe.SecretKey, in Input, share Share) error {

	ksin, ok := in.(*KeySwitchInput)
	if !ok {
		return fmt.Errorf("bad input type: %T instead of %T", in, ksin)
	}

	pkOut, ok := ksin.OutputKey.(*rlwe.PublicKey)
	if !ok {
		return fmt.Errorf("bad output key type: %T instead of %T", ksin.OutputKey, pkOut)
	}

	if ksin.InpuCt == nil {
		return fmt.Errorf("input ciphertext is nil")
	}

	pcksShare, ok := share.MHEShare.(*mhe.PublicKeySwitchShare)
	if !ok {
		return fmt.Errorf("bad share type: %T instead of %T", share.MHEShare, pcksShare)
	}

	cks.PublicKeySwitchProtocol.GenShare(sk, pkOut, ksin.InpuCt, pcksShare)

	return nil
}

func (cks *PCKSProtocol) Finalize(in Input, aggShare Share, rec interface{}) error {

	ksin, ok := in.(*KeySwitchInput)
	if !ok {
		return fmt.Errorf("bad input type: %T instead of %T", in, ksin)
	}

	if ksin.InpuCt == nil {
		return fmt.Errorf("input ciphertext is nil")
	}

	pcksAggShare, ok := aggShare.MHEShare.(*mhe.PublicKeySwitchShare)
	if !ok {
		return fmt.Errorf("bad share type: %T instead of %T", aggShare.MHEShare, pcksAggShare)
	}

	outCt, ok := rec.(*rlwe.Ciphertext)
	if !ok {
		return fmt.Errorf("bad receiver type: %T instead of %T", rec, outCt)
	}

	cks.PublicKeySwitchProtocol.KeySwitch(ksin.InpuCt, *pcksAggShare, outCt)
	return nil
}
