package pkg

import (
	"github.com/tuneinsight/lattigo/v4/drlwe"
	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe/ringqp"
	"github.com/tuneinsight/lattigo/v4/utils/sampling"
)

func GetTestSecretKeys(sessParams SessionParameters, nodeid NodeID) (sk *rlwe.SecretKey, tsk *drlwe.ShamirSecretShare, err error) {
	params, err := rlwe.NewParametersFromLiteral(sessParams.RLWEParams.RLWEParametersLiteral())
	if err != nil {
		return nil, nil, err
	}

	prng, err := sampling.NewKeyedPRNG([]byte{})
	if err != nil {
		return nil, nil, err
	}

	ts, err := ring.NewTernarySampler(prng, params.RingQ(), ring.Ternary{P: 0.5}, false) // ring.NewTernarySampler(prng, params.RingQ(), 0.5, false)
	if err != nil {
		return nil, nil, err
	}

	sks := make([]*rlwe.SecretKey, len(sessParams.Nodes))
	var index int
	for i, ni := range sessParams.Nodes {

		if ni == nodeid {
			index = i
		}

		sk := new(rlwe.SecretKey)
		ringQP := params.RingQP()
		sk.Value = ringQP.NewPoly()
		levelQ, levelP := sk.LevelQ(), sk.LevelP()
		ts.Read(sk.Value.Q)

		if levelP > -1 {
			ringQP.ExtendBasisSmallNormAndCenter(sk.Value.Q, levelP, sk.Value.Q, sk.Value.P)
		}

		ringQP.AtLevel(levelQ, levelP).NTT(sk.Value, sk.Value)
		ringQP.AtLevel(levelQ, levelP).MForm(sk.Value, sk.Value)
		sks[i] = sk
	}

	if sessParams.T == 0 || sessParams.T == len(sessParams.Nodes) {
		return sks[index], nil, nil
	}

	shares := make(map[NodeID]map[NodeID]drlwe.ShamirSecretShare, len(sessParams.Nodes))
	thresholdizer := drlwe.NewThresholdizer(params)
	usampler := ringqp.NewUniformSampler(prng, *params.RingQP())

	for i, ni := range sessParams.Nodes {

		shares[ni] = make(map[NodeID]drlwe.ShamirSecretShare, len(sessParams.Nodes))
		sk := sks[i]
		if err != nil {
			panic(err)
		}

		//shamirPoly, _ := thresholdizer.GenShamirPolynomial(sessParams.T, sk)
		shamirPoly := drlwe.ShamirPolynomial{Value: make([]ringqp.Poly, int(sessParams.T))}
		shamirPoly.Value[0] = *sk.Value.CopyNew()
		for i := 1; i < sessParams.T; i++ {
			shamirPoly.Value[i] = params.RingQP().NewPoly()
			usampler.Read(shamirPoly.Value[i])
		}

		for _, nj := range sessParams.Nodes {
			share := thresholdizer.AllocateThresholdSecretShare()
			thresholdizer.GenShamirSecretShare(sessParams.ShamirPks[nj], shamirPoly, &share)
			shares[ni][nj] = share
		}
	}

	tsks := make([]*drlwe.ShamirSecretShare, len(sessParams.Nodes))
	for i, ni := range sessParams.Nodes {
		tsk := thresholdizer.AllocateThresholdSecretShare()
		for _, nj := range sessParams.Nodes {
			thresholdizer.AggregateShares(shares[nj][ni], tsk, &tsk)
		}
		tsks[i] = &tsk
	}

	return sks[index], tsks[index], nil
}
