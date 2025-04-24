package sessions

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	drlwe "github.com/tuneinsight/lattigo/v5/mhe"
	"github.com/tuneinsight/lattigo/v5/ring/ringqp"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"
)

type TestSession struct {
	SessParams    Parameters
	FHEParameters FHEParameters
	RlweParams    rlwe.Parameters
	SkIdeal       *rlwe.SecretKey
	NodeSessions  map[NodeID]*Session
	HelperSession *Session

	// key backend
	*CachedKeyBackend

	// lattigo helpers
	//Encoder   *bgv.Encoder
	KeyGen    *rlwe.KeyGenerator
	Encryptor *rlwe.Encryptor
	Decryptor *rlwe.Decryptor
}

func NewTestSession(N, T int, fheParamLitteral FHEParamerersLiteralProvider, helperID NodeID) (*TestSession, error) {
	nids := make([]NodeID, N)
	nspk := make(map[NodeID]drlwe.ShamirPublicPoint)
	for i := range nids {
		nids[i] = NodeID(fmt.Sprintf("node-%d", i))
		nspk[nids[i]] = drlwe.ShamirPublicPoint(i + 1)
	}

	var sessParams = Parameters{
		ID:            "testsess",
		FHEParameters: fheParamLitteral,
		Threshold:     T,
		Nodes:         nids,
		ShamirPks:     nspk,
		PublicSeed:    []byte{'c', 'r', 's'},
	}

	return NewTestSessionFromParams(sessParams, helperID)

}

func NewTestSessionFromParams(sp Parameters, helperID NodeID) (*TestSession, error) {
	ts := new(TestSession)

	ts.SessParams = sp

	var err error
	ts.FHEParameters, err = NewFHEParameters(sp.FHEParameters)
	if err != nil {
		return nil, err
	}
	ts.RlweParams = *ts.FHEParameters.GetRLWEParameters()

	// Generates test session secrets for the nodes
	nodeSecrets, err := GenTestSecretKeys(sp)
	if err != nil {
		return nil, err
	}

	ts.SkIdeal = rlwe.NewSecretKey(ts.RlweParams)
	ts.NodeSessions = make(map[NodeID]*Session, len(sp.Nodes))
	for _, nid := range sp.Nodes {

		spi := sp

		// computes the ideal secret-key for the test
		ts.NodeSessions[nid], err = NewSession(nid, spi, nodeSecrets[nid])
		if err != nil {
			return nil, err
		}
		sk, err := ts.NodeSessions[nid].GetSecretKey()
		if err != nil {
			return nil, err
		}
		ts.RlweParams.RingQP().AtLevel(ts.SkIdeal.Value.Q.Level(), ts.SkIdeal.Value.P.Level()).Add(sk.Value, ts.SkIdeal.Value, ts.SkIdeal.Value)
	}

	ts.HelperSession, err = NewSession(helperID, sp, nil)
	if err != nil {
		return nil, err
	}

	ts.CachedKeyBackend = NewCachedPublicKeyBackend(NewTestKeyBackend(ts.RlweParams, ts.SkIdeal))

	ts.KeyGen = rlwe.NewKeyGenerator(ts.RlweParams)
	ts.Encryptor = rlwe.NewEncryptor(ts.RlweParams, ts.SkIdeal)
	ts.Decryptor = rlwe.NewDecryptor(ts.RlweParams, ts.SkIdeal)
	return ts, nil
}

func GenTestSecretKeys(sessParams Parameters) (secs map[NodeID]*Secrets, err error) {
	params, err := rlwe.NewParametersFromLiteral(sessParams.FHEParameters.GetRLWEParametersLiteral())
	if err != nil {
		return nil, err
	}

	secs = make(map[NodeID]*Secrets, len(sessParams.Nodes))
	for _, nid := range sessParams.Nodes {
		ss := new(Secrets)
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
