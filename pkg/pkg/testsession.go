package pkg

import (
	"fmt"

	"github.com/ldsec/helium/pkg/objectstore"
	"github.com/tuneinsight/lattigo/v4/bgv"
	"github.com/tuneinsight/lattigo/v4/drlwe"
	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe/ringqp"
	"github.com/tuneinsight/lattigo/v4/utils/sampling"
)

type TestSession struct {
	SessParams    SessionParameters
	RlweParams    bgv.Parameters
	SkIdeal       *rlwe.SecretKey
	NodeSessions  map[NodeID]*Session
	HelperSession *Session

	// key backend
	*CachedKeyBackend

	// lattigo helpers
	Encoder   *bgv.Encoder
	Encryptor *rlwe.Encryptor
	Decrpytor *rlwe.Decryptor
}

func NewTestSession(N, T int, rlweparams bgv.ParametersLiteral, helperId NodeID) (*TestSession, error) {
	nids := make([]NodeID, N)
	nspk := make(map[NodeID]drlwe.ShamirPublicPoint)
	for i := range nids {
		nids[i] = NodeID(fmt.Sprintf("node-%d", i))
		nspk[nids[i]] = drlwe.ShamirPublicPoint(i + 1)
	}

	var sessParams = SessionParameters{
		ID:         "testsess",
		RLWEParams: rlweparams,
		T:          T,
		Nodes:      nids,
		ShamirPks:  nspk,
		PublicSeed: []byte{'c', 'r', 's'},
	}

	return NewTestSessionFromParams(sessParams, helperId)

}

func NewTestSessionFromParams(sp SessionParameters, helperId NodeID) (*TestSession, error) {
	ts := new(TestSession)

	ts.SessParams = sp

	var err error
	ts.RlweParams, err = bgv.NewParametersFromLiteral(sp.RLWEParams)
	if err != nil {
		panic(err)
	}

	ts.SkIdeal = rlwe.NewSecretKey(ts.RlweParams)
	ts.NodeSessions = make(map[NodeID]*Session, len(sp.Nodes))
	for _, nid := range sp.Nodes {

		os, err := objectstore.NewObjectStoreFromConfig(objectstore.Config{BackendName: "mem"})
		if err != nil {
			return nil, err
		}

		// computes the ideal secret-key for the test
		ts.NodeSessions[nid], err = NewSession(sp, nid, os)
		if err != nil {
			return nil, err
		}
		sk, err := ts.NodeSessions[nid].GetSecretKey()
		if err != nil {
			return nil, err
		}
		ts.RlweParams.RingQP().AtLevel(ts.SkIdeal.Value.Q.Level(), ts.SkIdeal.Value.P.Level()).Add(sk.Value, ts.SkIdeal.Value, ts.SkIdeal.Value)
	}

	os, err := objectstore.NewObjectStoreFromConfig(objectstore.Config{BackendName: "mem"})
	if err != nil {
		return nil, err
	}

	ts.HelperSession, err = NewSession(sp, helperId, os)

	ts.CachedKeyBackend = NewCachedPublicKeyBackend(NewTestKeyBackend(ts.RlweParams.Parameters, ts.SkIdeal))

	ts.Encoder = bgv.NewEncoder(ts.RlweParams)
	ts.Encryptor, err = bgv.NewEncryptor(ts.RlweParams, ts.SkIdeal)
	if err != nil {
		return nil, err
	}
	ts.Decrpytor, err = bgv.NewDecryptor(ts.RlweParams, ts.SkIdeal)

	return ts, err
}

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
