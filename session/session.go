// Package session implements helium sessions.
package session

import (
	"context"
	"fmt"
	"slices"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/utils"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	drlwe "github.com/tuneinsight/lattigo/v5/mhe"
	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"
)

// Session holds the session's critical state.
type Session struct {
	Parameters
	NodeID helium.NodeID
	Params bgv.Parameters

	secretKey *rlwe.SecretKey
	rlkEphSk  *rlwe.SecretKey
}

type Secrets struct {
	PrivateSeed        []byte
	ThresholdSecretKey *drlwe.ShamirSecretShare
}

// Parameters contains data used to initialize a Session.
type Parameters struct {
	ID         helium.SessionID
	Nodes      []helium.NodeID
	RLWEParams bgv.ParametersLiteral
	Threshold  int
	ShamirPks  map[helium.NodeID]drlwe.ShamirPublicPoint
	PublicSeed []byte
	*Secrets
}

// NewSession creates a new session.
func NewSession(sessParams Parameters, nodeID helium.NodeID) (sess *Session, err error) {
	sess = new(Session)
	sess.NodeID = nodeID
	//sess.ObjectStore = objStore

	if len(sessParams.ID) == 0 {
		return nil, fmt.Errorf("invalid session parameters: unspecified session id")
	}
	sess.ID = sessParams.ID

	if len(sessParams.Nodes) < 2 {
		return nil, fmt.Errorf("invalid session parameters: less than two session nodes")
	}
	sess.Nodes = slices.Clone(sessParams.Nodes)

	if sessParams.Threshold > len(sessParams.Nodes) {
		return nil, fmt.Errorf("invalid session parameters: threshold greater than number of session nodes")
	}
	if sessParams.Threshold > 0 {
		sess.Threshold = sessParams.Threshold
	} else {
		sess.Threshold = len(sessParams.Nodes)
	}

	if len(sessParams.PublicSeed) == 0 {
		return nil, fmt.Errorf("invalid session parameters: unspecified public seed")
	}
	sess.PublicSeed = slices.Clone(sessParams.PublicSeed)

	sess.ShamirPks = make(map[helium.NodeID]drlwe.ShamirPublicPoint, len(sessParams.ShamirPks))
	for _, nid := range sess.Nodes {
		var has bool
		if sess.ShamirPks[nid], has = sessParams.ShamirPks[nid]; !has {
			return nil, fmt.Errorf("invalid session parameters: missing Shamir public point for node %s", nid)
		}
	}

	sess.RLWEParams = sessParams.RLWEParams
	sess.Params, err = bgv.NewParametersFromLiteral(sessParams.RLWEParams)
	if err != nil {
		return nil, fmt.Errorf("could not create session parameters: %s", err)
	}

	// node re-generates its secret-key material for the session
	if utils.NewSet(sessParams.Nodes).Contains(nodeID) {

		if sessParams.Secrets == nil || len(sessParams.Secrets.PrivateSeed) == 0 {
			return nil, fmt.Errorf("session nodes must specify session secrets")
		}

		sess.Secrets = new(Secrets)
		sess.PrivateSeed = slices.Clone(sessParams.Secrets.PrivateSeed)

		sessPrng, err := sampling.NewKeyedPRNG(sessParams.Secrets.PrivateSeed)
		if err != nil {
			return nil, fmt.Errorf("could not create session PRNG: %s", err)
		}

		sess.secretKey, err = genSecretKey(sess.Params, sessPrng)
		if err != nil {
			return nil, fmt.Errorf("could not generate secret key: %s", err)
		}

		sess.rlkEphSk, err = genSecretKey(sess.Params, sessPrng)
		if err != nil {
			return nil, fmt.Errorf("could not generate rlk eph secret key: %s", err)
		}

		if sessParams.Threshold < len(sessParams.Nodes) {
			if sessParams.ThresholdSecretKey == nil {
				return nil, fmt.Errorf("session nodes must specify threshold secret key when session threshold is less than the number of nodes")
			}
			sess.ThresholdSecretKey = &drlwe.ShamirSecretShare{Poly: *sessParams.ThresholdSecretKey.CopyNew()} // TODO: add copy method to Lattigo
		}
	}

	return sess, nil
}

func genSecretKey(pp rlwe.ParameterProvider, prng sampling.PRNG) (sk *rlwe.SecretKey, err error) {

	params := pp.GetRLWEParameters()

	ts, err := ring.NewSampler(prng, params.RingQ(), params.Xs(), false)
	if err != nil {
		return nil, err
	}

	sk = new(rlwe.SecretKey)
	ringQP := params.RingQP()
	sk.Value = ringQP.NewPoly()
	levelQ, levelP := sk.LevelQ(), sk.LevelP()
	ts.Read(sk.Value.Q)

	if levelP > -1 {
		ringQP.ExtendBasisSmallNormAndCenter(sk.Value.Q, levelP, sk.Value.Q, sk.Value.P)
	}

	ringQP.AtLevel(levelQ, levelP).NTT(sk.Value, sk.Value)
	ringQP.AtLevel(levelQ, levelP).MForm(sk.Value, sk.Value)
	return
}

func (sess *Session) GetSecretKeyForGroup(parties []helium.NodeID) (sk *rlwe.SecretKey, err error) {
	switch {
	case len(parties) == len(sess.Nodes):
		if sess.secretKey == nil {
			return nil, fmt.Errorf("party has no secret-key in the session")
		}
		return sess.secretKey, nil
	case len(parties) >= sess.Threshold:
		sk = rlwe.NewSecretKey(sess.Params)
		spks := make([]drlwe.ShamirPublicPoint, len(parties))
		for i, pid := range parties {
			var has bool
			if spks[i], has = sess.ShamirPks[pid]; !has {
				return nil, fmt.Errorf("unknown Shamir public point for party %s", pid)
			}
		}
		if sess.ThresholdSecretKey == nil {
			return nil, fmt.Errorf("node has no threshold secret key")
		}
		drlwe.NewCombiner(*sess.Params.GetRLWEParameters(),
			sess.GetShamirPublicPoints()[sess.NodeID],
			sess.GetShamirPublicPointsList(),
			sess.Threshold).GenAdditiveShare(spks, sess.ShamirPks[sess.NodeID], *sess.ThresholdSecretKey, sk)
		return sk, nil
	default:
		return nil, fmt.Errorf("group of size %d is not enough participants to reconstruct", len(parties))
	}
}

// GetSecretKey loads the secret key from the ObjectStore.
func (sess *Session) GetSecretKey() (*rlwe.SecretKey, error) {
	if sess.secretKey == nil {
		return nil, fmt.Errorf("node has no secret-key in the session")
	}
	return sess.secretKey, nil
}

func (sess *Session) GetRLKEphemeralSecretKey() (*rlwe.SecretKey, error) {
	if sess.rlkEphSk == nil {
		return nil, fmt.Errorf("node has no rlk ephemeral secret-key in the session")
	}
	return sess.rlkEphSk, nil
}

// GetThresholdSecretKey loads the secret key from the ObjectStore.
func (sess *Session) GetThresholdSecretKey() (*drlwe.ShamirSecretShare, error) {
	if sess.ThresholdSecretKey == nil {
		return nil, fmt.Errorf("node has no threshold secret-key in the session")
	}
	return sess.ThresholdSecretKey, nil
}

func (sess *Session) GetShamirPublicPoints() map[helium.NodeID]drlwe.ShamirPublicPoint {
	spts := make(map[helium.NodeID]drlwe.ShamirPublicPoint, len(sess.ShamirPks))
	for p, spt := range sess.ShamirPks {
		spts[p] = spt
	}
	return spts
}

func (sess *Session) GetShamirPublicPointsList() []drlwe.ShamirPublicPoint {
	spts := make([]drlwe.ShamirPublicPoint, 0, len(sess.ShamirPks))
	for _, spt := range sess.ShamirPks {
		spts = append(spts, spt)
	}
	return spts
}

func (sess *Session) Contains(nodeID helium.NodeID) bool {
	return utils.NewSet(sess.Nodes).Contains(nodeID)
}

func (sess *Session) GetSessionFromID(sessionID helium.SessionID) (*Session, bool) {
	if sess.ID == sessionID {
		return sess, true
	}
	return nil, false
}

func (sess *Session) GetSessionFromContext(ctx context.Context) (*Session, bool) {
	sessID, has := helium.SessionIDFromContext(ctx)
	if !has {
		return nil, false
	}
	return sess.GetSessionFromID(sessID)
}

func (sess *Session) String() string {
	return fmt.Sprintf(`
	{
		ID: %s,
		NodeID: %s,
		Nodes: %v,
		T: %d,
		CRSKey: %v,
	}`, sess.ID, sess.NodeID, sess.Nodes, sess.Threshold, sess.PublicSeed)
}
