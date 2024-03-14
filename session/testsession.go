package session

import (
	"fmt"

	"github.com/ldsec/helium"
	"github.com/tuneinsight/lattigo/v4/bgv"
	"github.com/tuneinsight/lattigo/v4/drlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe/ringqp"
	"github.com/tuneinsight/lattigo/v4/utils/sampling"
)

type TestSession struct {
	SessParams    Parameters
	RlweParams    bgv.Parameters
	SkIdeal       *rlwe.SecretKey
	NodeSessions  map[helium.NodeID]*Session
	HelperSession *Session

	// key backend
	*helium.CachedKeyBackend

	// lattigo helpers
	Encoder   *bgv.Encoder
	Encryptor *rlwe.Encryptor
	Decrpytor *rlwe.Decryptor
}

func NewTestSession(N, T int, rlweparams bgv.ParametersLiteral, helperID helium.NodeID) (*TestSession, error) {
	nids := make([]helium.NodeID, N)
	nspk := make(map[helium.NodeID]drlwe.ShamirPublicPoint)
	for i := range nids {
		nids[i] = helium.NodeID(fmt.Sprintf("node-%d", i))
		nspk[nids[i]] = drlwe.ShamirPublicPoint(i + 1)
	}

	var sessParams = Parameters{
		ID:         "testsess",
		RLWEParams: rlweparams,
		Threshold:  T,
		Nodes:      nids,
		ShamirPks:  nspk,
		PublicSeed: []byte{'c', 'r', 's'},
	}

	return NewTestSessionFromParams(sessParams, helperID)

}

func NewTestSessionFromParams(sp Parameters, helperID helium.NodeID) (*TestSession, error) {
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
	ts.NodeSessions = make(map[helium.NodeID]*Session, len(sp.Nodes))
	for _, nid := range sp.Nodes {

		spi := sp
		spi.Secrets = nodeSecrets[nid]

		// computes the ideal secret-key for the test
		ts.NodeSessions[nid], err = NewSession(spi, nid)
		if err != nil {
			return nil, err
		}
		sk, err := ts.NodeSessions[nid].GetSecretKey()
		if err != nil {
			return nil, err
		}
		ts.RlweParams.RingQP().AtLevel(ts.SkIdeal.Value.Q.Level(), ts.SkIdeal.Value.P.Level()).Add(sk.Value, ts.SkIdeal.Value, ts.SkIdeal.Value)
	}

	ts.HelperSession, err = NewSession(sp, helperID)
	if err != nil {
		return nil, err
	}

	ts.CachedKeyBackend = helium.NewCachedPublicKeyBackend(helium.NewTestKeyBackend(ts.RlweParams.Parameters, ts.SkIdeal))

	ts.Encoder = bgv.NewEncoder(ts.RlweParams)
	ts.Encryptor, err = bgv.NewEncryptor(ts.RlweParams, ts.SkIdeal)
	if err != nil {
		return nil, err
	}
	ts.Decrpytor, err = bgv.NewDecryptor(ts.RlweParams, ts.SkIdeal)

	return ts, err
}

func GenTestSecretKeys(sessParams Parameters) (secs map[helium.NodeID]*Secrets, err error) {
	params, err := rlwe.NewParametersFromLiteral(sessParams.RLWEParams.RLWEParametersLiteral())
	if err != nil {
		return nil, err
	}

	secs = make(map[helium.NodeID]*Secrets, len(sessParams.Nodes))
	for _, nid := range sessParams.Nodes {
		ss := new(Secrets)
		secs[nid] = ss
		ss.PrivateSeed = []byte(nid) // uses the node id as the private seed for testing
	}

	if sessParams.Threshold == 0 || sessParams.Threshold == len(sessParams.Nodes) {
		return secs, nil
	}

	// simulates the generation of the shamir threshold keys
	shares := make(map[helium.NodeID]map[helium.NodeID]drlwe.ShamirSecretShare, len(sessParams.Nodes))
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

		shares[nidi] = make(map[helium.NodeID]drlwe.ShamirSecretShare, len(sessParams.Nodes))

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