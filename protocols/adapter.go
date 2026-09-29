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
	allocateShare() Share
	readCRP(crs mhe.CRS) (CRP, error)
	genShare(rlwe.PRNGs, *rlwe.SecretKey, Input, Share) error
	aggregatedShares(dst Share, ss ...Share) error
	finalize(in Input, agg Share, outRec interface{}) error
}

// checkPRNGs checks that the PRNGs passed to a genShare method have their private PRNG set.
// Lattigo falls back to a non-deterministic PRNG when the private PRNG is not set, in which
// case a node restarting a protocol would generate a new share from fresh randomness. This
// is insecure, as the difference between two shares with the same public randomness can leak
// information about the secret key.
func checkPRNGs(prngs rlwe.PRNGs) error {
	if prngs.PrivatePRNG == nil {
		return fmt.Errorf("private PRNG must be set")
	}
	return nil
}

// lattigoShare is a common interface for all Lattigo shares
type lattigoShare interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

func newMHEProtocol(sig Signature, params rlwe.Parameters) (mheProtocol, error) {
	switch sig.Type {
	case CKG:
		return newCKGProtocol(params, sig.Args)
	case RTG:
		return newRTGProtocol(params, sig.Args)
	case RKG1:
		return newRKGProtocol(params, nil, 1, sig.Args)
	case RKG:
		return newRKGProtocol(params, nil, 2, sig.Args)
	case CKS:
		return newCKSProtocol(params, sig.Args)
	case DEC:
		return newCKSProtocol(params, sig.Args)
	case PCKS:
		return newPCKSProtocol(params, sig.Args)
	default:
		return nil, fmt.Errorf("unsupported MHE protocol type: %s", sig.Type)
	}
}

type SKGProtocol struct {
	mhe.Thresholdizer
}

type ckgProtocol struct {
	mhe.PublicKeyGenProtocol
	params *rlwe.Parameters
}

func newCKGProtocol(params rlwe.Parameters, arg map[string]string) (*ckgProtocol, error) {
	return &ckgProtocol{PublicKeyGenProtocol: mhe.NewPublicKeyGenProtocol(params), params: &params}, nil
}

func (ckg *ckgProtocol) allocateShare() Share {
	s := ckg.PublicKeyGenProtocol.AllocateShare()
	return Share{MHEShare: &s}
}

func (ckg *ckgProtocol) readCRP(crs mhe.CRS) (CRP, error) {
	return ckg.PublicKeyGenProtocol.SampleCRP(crs), nil
}

func (ckg *ckgProtocol) genShare(prngs rlwe.PRNGs, sk *rlwe.SecretKey, crp Input, share Share) error {
	if err := checkPRNGs(prngs); err != nil {
		return err
	}
	ckgcrp, ok := crp.(mhe.PublicKeyGenCRP)
	if !ok {
		return fmt.Errorf("bad input type: %T instead of %T", crp, ckgcrp)
	}
	ckgShare, ok := share.MHEShare.(*mhe.PublicKeyGenShare)
	if !ok {
		return fmt.Errorf("bad share type: %T instead of %T", share, ckgShare)
	}
	ckg.PublicKeyGenProtocol.GenShare(sk, ckgcrp, ckgShare, prngs)
	return nil
}

func (ckg *ckgProtocol) aggregatedShares(dst Share, ss ...Share) error {

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

func (ckg *ckgProtocol) finalize(crp Input, aggShare Share, rec interface{}) error {
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

type rtgProtocol struct {
	mhe.GaloisKeyGenProtocol
	galEl  uint64 // TODO passed as argument ?
	params *rlwe.Parameters
}

func newRTGProtocol(params rlwe.Parameters, args map[string]string) (*rtgProtocol, error) {
	if _, hasArg := args["GalEl"]; !hasArg {
		return nil, fmt.Errorf("should provide argument: GalEl")
	}

	galEl, err := strconv.ParseUint(args["GalEl"], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid galois element type: %T instead of %T", args["GalEl"], galEl)
	}

	return &rtgProtocol{galEl: galEl, GaloisKeyGenProtocol: mhe.NewGaloisKeyGenProtocol(params), params: &params}, nil
}

func (rtg *rtgProtocol) allocateShare() Share {
	s := rtg.GaloisKeyGenProtocol.AllocateShare()
	return Share{MHEShare: &s}
}

func (rtg *rtgProtocol) readCRP(crs mhe.CRS) (CRP, error) {
	return rtg.GaloisKeyGenProtocol.SampleCRP(crs), nil
}

func (rtg *rtgProtocol) genShare(prngs rlwe.PRNGs, sk *rlwe.SecretKey, crp Input, share Share) error {
	if err := checkPRNGs(prngs); err != nil {
		return err
	}
	rtgcrp, ok := crp.(mhe.GaloisKeyGenCRP)
	if !ok {
		return fmt.Errorf("bad input type: %T", crp)
	}
	rtgShare, ok := share.MHEShare.(*mhe.GaloisKeyGenShare)
	if !ok {
		return fmt.Errorf("bad share type: %T", share)
	}
	return rtg.GaloisKeyGenProtocol.GenShare(sk, rtg.galEl, rtgcrp, rtgShare, prngs)
}

func (rtg *rtgProtocol) aggregatedShares(dst Share, ss ...Share) error {
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

func (rtg *rtgProtocol) finalize(crp Input, aggShare Share, rec interface{}) error {
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

type rkgProtocol struct {
	mhe.RelinearizationKeyGenProtocol
	params *rlwe.Parameters

	round uint64
	ephSk *rlwe.SecretKey
}

func newRKGProtocol(params rlwe.Parameters, ephSk *rlwe.SecretKey, round uint64, _ map[string]string) (*rkgProtocol, error) {
	return &rkgProtocol{RelinearizationKeyGenProtocol: mhe.NewRelinearizationKeyGenProtocol(params), params: &params, round: round, ephSk: ephSk}, nil
}

func (rkg *rkgProtocol) allocateShare() (share Share) {
	_, s1, _ := rkg.RelinearizationKeyGenProtocol.AllocateShare()
	return Share{MHEShare: &s1}
}

func (rkg *rkgProtocol) aggregatedShares(dst Share, ss ...Share) error {
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

func (rkg *rkgProtocol) readCRP(crs mhe.CRS) (CRP, error) {
	return rkg.RelinearizationKeyGenProtocol.SampleCRP(crs), nil
}

func (rkg *rkgProtocol) genShare(prngs rlwe.PRNGs, sk *rlwe.SecretKey, input Input, share Share) error {
	if err := checkPRNGs(prngs); err != nil {
		return err
	}
	rkgShare, ok := share.MHEShare.(*mhe.RelinearizationKeyGenShare)
	if !ok {
		return fmt.Errorf("invalid share type: %T instead of %T", share, rkgShare)
	}
	if rkg.round == 1 {
		rkgcrp, ok := input.(mhe.RelinearizationKeyGenCRP)
		if !ok {
			return fmt.Errorf("bad input type: %T instead of %T", input, rkgcrp)
		}
		rkg.RelinearizationKeyGenProtocol.GenShareRoundOne(sk, rkgcrp, rkg.ephSk, rkgShare, prngs)
	} else {
		rkgShareRoundOne, ok := input.(*mhe.RelinearizationKeyGenShare)
		if !ok {
			return fmt.Errorf("bad input type: %T instead of %T", input, rkgShareRoundOne)
		}
		rkg.RelinearizationKeyGenProtocol.GenShareRoundTwo(rkg.ephSk, sk, *rkgShareRoundOne, rkgShare, prngs)
	}

	return nil
}

func (rkg *rkgProtocol) finalize(round1 Input, aggShares Share, rec interface{}) error {

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

type cksProtocol struct {
	maxLevel int
	mhe.KeySwitchProtocol
}

func newCKSProtocol(params rlwe.Parameters, args map[string]string) (*cksProtocol, error) {
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
	return &cksProtocol{maxLevel: params.MaxLevel(), KeySwitchProtocol: p}, nil
}

func (cks *cksProtocol) allocateShare() Share {
	s := cks.KeySwitchProtocol.AllocateShare(cks.maxLevel)
	return Share{MHEShare: &s}
}

func (cks *cksProtocol) readCRP(crs mhe.CRS) (CRP, error) {
	panic("CKS protocol does not require a CRP")
}

func (cks *cksProtocol) aggregatedShares(dst Share, ss ...Share) error {
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

func (cks *cksProtocol) genShare(prngs rlwe.PRNGs, sk *rlwe.SecretKey, in Input, share Share) error {

	if err := checkPRNGs(prngs); err != nil {
		return err
	}

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

	cks.KeySwitchProtocol.GenShare(sk, skOut, ksin.InpuCt, cksShare, prngs)

	return nil
}

func (cks *cksProtocol) finalize(in Input, aggShare Share, rec interface{}) error {

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

type pcksProtocol struct {
	maxLevel int
	mhe.PublicKeySwitchProtocol
}

func newPCKSProtocol(params rlwe.Parameters, args map[string]string) (*pcksProtocol, error) {
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
	return &pcksProtocol{maxLevel: params.MaxLevel(), PublicKeySwitchProtocol: p}, nil
}

func (cks *pcksProtocol) allocateShare() Share {
	s := cks.PublicKeySwitchProtocol.AllocateShare(cks.maxLevel)
	return Share{MHEShare: &s}
}

func (cks *pcksProtocol) readCRP(crs mhe.CRS) (CRP, error) {
	panic("PCKS protocol does not require a CRP")
}

func (cks *pcksProtocol) aggregatedShares(dst Share, ss ...Share) error {
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

func (cks *pcksProtocol) genShare(prngs rlwe.PRNGs, sk *rlwe.SecretKey, in Input, share Share) error {

	if err := checkPRNGs(prngs); err != nil {
		return err
	}

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

	cks.PublicKeySwitchProtocol.GenShare(sk, pkOut, ksin.InpuCt, pcksShare, prngs)

	return nil
}

func (cks *pcksProtocol) finalize(in Input, aggShare Share, rec interface{}) error {

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
