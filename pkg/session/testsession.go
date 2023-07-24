package pkg

import (
	"github.com/tuneinsight/lattigo/v4/drlwe"
	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe/ringqp"
	"github.com/tuneinsight/lattigo/v4/utils"
)

func GetTestSecretKeys(sessParams SessionParameters, nodeid NodeID) (sk *rlwe.SecretKey, tsk *drlwe.ShamirSecretShare, err error) {
	params, err := rlwe.NewParametersFromLiteral(sessParams.RLWEParams)
	if err != nil {
		return nil, nil, err
	}

	prng, err := utils.NewKeyedPRNG([]byte{})
	if err != nil {
		return nil, nil, err
	}

	ts := ring.NewTernarySampler(prng, params.RingQ(), 0.5, false)

	sks := make([]*rlwe.SecretKey, len(sessParams.Nodes))
	for i := range sks {
		sk := new(rlwe.SecretKey)
		ringQP := params.RingQP()
		sk.Value = ringQP.NewPoly()
		levelQ, levelP := sk.LevelQ(), sk.LevelP()
		ts.Read(sk.Value.Q)

		if levelP > -1 {
			ringQP.ExtendBasisSmallNormAndCenter(sk.Value.Q, levelP, nil, sk.Value.P)
		}

		ringQP.NTTLvl(levelQ, levelP, sk.Value, sk.Value)
		ringQP.MFormLvl(levelQ, levelP, sk.Value, sk.Value)
		sks[i] = sk
	}

	if sessParams.T == 0 || sessParams.T == len(sessParams.Nodes) {
		return
	}

	shares := make(map[NodeID]map[NodeID]*drlwe.ShamirSecretShare, len(sessParams.Nodes))
	thresholdizer := drlwe.NewThresholdizer(params)
	usampler := ringqp.NewUniformSampler(prng, *params.RingQP())

	var index int

	for i, ni := range sessParams.Nodes {

		if ni == nodeid {
			index = i
		}

		shares[ni] = make(map[NodeID]*drlwe.ShamirSecretShare, len(sessParams.Nodes))
		sk := sks[i]
		if err != nil {
			panic(err)
		}

		//shamirPoly, _ := thresholdizer.GenShamirPolynomial(sessParams.T, sk)
		shamirPoly := &drlwe.ShamirPolynomial{Coeffs: make([]ringqp.Poly, int(sessParams.T))}
		shamirPoly.Coeffs[0] = sk.Value.CopyNew()
		for i := 1; i < sessParams.T; i++ {
			shamirPoly.Coeffs[i] = params.RingQP().NewPoly()
			usampler.Read(shamirPoly.Coeffs[i])
		}

		for _, nj := range sessParams.Nodes {
			shares[ni][nj] = thresholdizer.AllocateThresholdSecretShare()
			thresholdizer.GenShamirSecretShare(sessParams.ShamirPks[nj], shamirPoly, shares[ni][nj])
		}
	}

	tsks := make([]*drlwe.ShamirSecretShare, len(sessParams.Nodes))
	for i, ni := range sessParams.Nodes {
		tsk := thresholdizer.AllocateThresholdSecretShare()
		for _, nj := range sessParams.Nodes {
			thresholdizer.AggregateShares(shares[nj][ni], tsk, tsk)
		}
		tsks[i] = tsk
	}

	return sks[index], tsks[index], nil
}
