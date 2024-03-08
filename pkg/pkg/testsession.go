package pkg

import (
	"fmt"

	"github.com/ldsec/helium/pkg/objectstore"
	"github.com/tuneinsight/lattigo/v4/bgv"
	"github.com/tuneinsight/lattigo/v4/drlwe"
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
		Threshold:  T,
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

	// Generates test session secrets for the nodes
	nodeSecrets, err := GenTestSecretKeys(sp)
	if err != nil {
		return nil, err
	}

	ts.SkIdeal = rlwe.NewSecretKey(ts.RlweParams)
	ts.NodeSessions = make(map[NodeID]*Session, len(sp.Nodes))
	for _, nid := range sp.Nodes {

		os, err := objectstore.NewObjectStoreFromConfig(objectstore.Config{BackendName: "mem"})
		if err != nil {
			return nil, err
		}

		spi := sp
		spi.SessionSecrets = nodeSecrets[nid]

		// computes the ideal secret-key for the test
		ts.NodeSessions[nid], err = NewSession(spi, nid, os)
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

func GenTestSecretKeys(sessParams SessionParameters) (secs map[NodeID]*SessionSecrets, err error) {
	params, err := rlwe.NewParametersFromLiteral(sessParams.RLWEParams.RLWEParametersLiteral())
	if err != nil {
		return nil, err
	}

	secs = make(map[NodeID]*SessionSecrets, len(sessParams.Nodes))
	for _, nid := range sessParams.Nodes {
		ss := new(SessionSecrets)
		secs[nid] = ss
		ss.PrivateSeed = []byte(nid) // uses the node id as the private seed for testing
	}

	if sessParams.Threshold == 0 || sessParams.Threshold == len(sessParams.Nodes) {
		return secs, nil
	}

	// simulates the generation of the shamir threshold keys
	shares := make(map[NodeID]map[NodeID]drlwe.ShamirSecretShare, len(sessParams.Nodes))
	thresholdizer := drlwe.NewThresholdizer(params)

	for nidi, ssi := range secs {

		prngi, err := sampling.NewKeyedPRNG(ssi.PrivateSeed)
		if err != nil {
			return nil, err
		}

		ski, err := genSecretKey(params, prngi)
		if err != nil {
			return nil, err
		}

		shares[nidi] = make(map[NodeID]drlwe.ShamirSecretShare, len(sessParams.Nodes))

		// TODO: add seeding to Thresholdizer and replace the following code with the Thresholdizer.GenShamirPolynomial method
		usampleri := ringqp.NewUniformSampler(prngi, *params.RingQP())
		shamirPoly := drlwe.ShamirPolynomial{Value: make([]ringqp.Poly, int(sessParams.Threshold))}
		shamirPoly.Value[0] = *ski.Value.CopyNew()
		for i := 1; i < sessParams.Threshold; i++ {
			shamirPoly.Value[i] = params.RingQP().NewPoly()
			usampleri.Read(shamirPoly.Value[i])
		}

		for _, nidj := range sessParams.Nodes {
			share := thresholdizer.AllocateThresholdSecretShare()
			thresholdizer.GenShamirSecretShare(sessParams.ShamirPks[nidj], shamirPoly, &share)
			shares[nidi][nidj] = share
		}
	}

	for _, nidi := range sessParams.Nodes {
		tsk := thresholdizer.AllocateThresholdSecretShare()
		secs[nidi].ThresholdSecretKey = &tsk
		for _, nidj := range sessParams.Nodes {
			thresholdizer.AggregateShares(shares[nidj][nidi], tsk, &tsk)
		}
	}

	return secs, nil
}
