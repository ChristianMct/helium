// Package heliumtest provides test fixtures for Helium applications and for the
// framework's own tests: local session fixtures with their key material, a key
// provider generating the setup keys on the fly, a library of test circuits and a
// local circuit runtime.
package heliumtest

import (
	"fmt"

	"github.com/ChristianMct/helium"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/mhe"
	"github.com/tuneinsight/lattigo/v5/ring/ringqp"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"
)

type Sessions struct {
	SessParams    helium.Parameters
	FHEParameters helium.FHEParameters
	RlweParams    rlwe.Parameters
	SkIdeal       *rlwe.SecretKey
	Nodes         map[helium.NodeID]*helium.Session
	Helper        *helium.Session

	// key backend
	*helium.CachedKeyBackend

	// lattigo helpers
	//Encoder   *bgv.Encoder
	KeyGen    *rlwe.KeyGenerator
	Encryptor *rlwe.Encryptor
	Decryptor *rlwe.Decryptor
}

func NewSessions(N, T int, fheParamLitteral helium.FHEParametersLiteralProvider, helperID helium.NodeID) (*Sessions, error) {
	nids := make([]helium.NodeID, N)
	nspk := make(map[helium.NodeID]mhe.ShamirPublicPoint)
	for i := range nids {
		nids[i] = helium.NodeID(fmt.Sprintf("node-%d", i))
		nspk[nids[i]] = mhe.ShamirPublicPoint(i + 1)
	}

	var sessParams = helium.Parameters{
		ID:            "testsess",
		FHEParameters: fheParamLitteral,
		Threshold:     T,
		Nodes:         nids,
		ShamirPks:     nspk,
		PublicSeed:    []byte{'c', 'r', 's'},
	}

	return NewSessionsFromParams(sessParams, helperID)

}

func NewSessionsFromParams(sp helium.Parameters, helperID helium.NodeID) (*Sessions, error) {
	ts := new(Sessions)

	ts.SessParams = sp

	var err error
	ts.FHEParameters, err = helium.NewFHEParameters(sp.FHEParameters)
	if err != nil {
		return nil, err
	}
	ts.RlweParams = *ts.FHEParameters.GetRLWEParameters()

	// Generates test session secrets for the nodes
	nodeSecrets, err := GenSecretKeys(sp)
	if err != nil {
		return nil, err
	}

	ts.SkIdeal = rlwe.NewSecretKey(ts.RlweParams)
	ts.Nodes = make(map[helium.NodeID]*helium.Session, len(sp.Nodes))
	for _, nid := range sp.Nodes {

		spi := sp

		// computes the ideal secret-key for the test
		ts.Nodes[nid], err = helium.NewSession(nid, spi, nodeSecrets[nid])
		if err != nil {
			return nil, err
		}
		sk, err := ts.Nodes[nid].GetSecretKey()
		if err != nil {
			return nil, err
		}
		ts.RlweParams.RingQP().AtLevel(ts.SkIdeal.Value.Q.Level(), ts.SkIdeal.Value.P.Level()).Add(sk.Value, ts.SkIdeal.Value, ts.SkIdeal.Value)
	}

	ts.Helper, err = helium.NewSession(helperID, sp, nil)
	if err != nil {
		return nil, err
	}

	ts.CachedKeyBackend = helium.NewCachedPublicKeyBackend(NewKeyProvider(ts.RlweParams, ts.SkIdeal))

	ts.KeyGen = rlwe.NewKeyGenerator(ts.RlweParams)
	ts.Encryptor = rlwe.NewEncryptor(ts.RlweParams, ts.SkIdeal)
	ts.Decryptor = rlwe.NewDecryptor(ts.RlweParams, ts.SkIdeal)
	return ts, nil
}

func GenSecretKeys(sessParams helium.Parameters) (secs map[helium.NodeID]*helium.Secrets, err error) {
	params, err := rlwe.NewParametersFromLiteral(sessParams.FHEParameters.GetRLWEParametersLiteral())
	if err != nil {
		return nil, err
	}

	secs = make(map[helium.NodeID]*helium.Secrets, len(sessParams.Nodes))
	for _, nid := range sessParams.Nodes {
		ss := new(helium.Secrets)
		secs[nid] = ss
		ss.PrivateSeed = []byte(nid) // uses the node id as the private seed for testing
	}

	if sessParams.Threshold == 0 || sessParams.Threshold == len(sessParams.Nodes) {
		return secs, nil
	}

	// simulates the generation of the shamir threshold keys
	shares := make(map[helium.NodeID]map[helium.NodeID]mhe.ShamirSecretShare, len(sessParams.Nodes))
	thresholdizer := mhe.NewThresholdizer(params)

	for nidi, ssi := range secs {

		prngi, err := sampling.NewKeyedPRNG(ssi.PrivateSeed)
		if err != nil {
			return nil, err
		}

		ski, err := helium.NewSecretKeyFromSeed(params, ssi.PrivateSeed)
		if err != nil {
			return nil, err
		}

		shares[nidi] = make(map[helium.NodeID]mhe.ShamirSecretShare, len(sessParams.Nodes))

		// TODO: add seeding to Thresholdizer and replace the following code with the Thresholdizer.GenShamirPolynomial method
		usampleri := ringqp.NewUniformSampler(prngi, *params.RingQP())
		shamirPoly := mhe.ShamirPolynomial{Value: make([]ringqp.Poly, int(sessParams.Threshold))}
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
