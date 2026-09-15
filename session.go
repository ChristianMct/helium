// Package helium provides the types and methods to implement an end-to-end MHE
// application: the vocabulary of a Helium session (node and session identifiers,
// parameters, key material), the language for defining circuits, and the contracts
// that an application implements (App) and is given (Runtime).
//
// A Helium application is defined by an App value and run on a node. The node
// implementations live in the setting-specific packages: helper for the
// helper-assisted setting. The runners executing the MHE protocols and the circuits
// live in the protocols and circuits packages; an application does not use them
// directly.
package helium

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/ChristianMct/helium/objectstore"
	"github.com/ChristianMct/helium/utils"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	drlwe "github.com/tuneinsight/lattigo/v5/mhe"
	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
	"github.com/tuneinsight/lattigo/v5/schemes/ckks"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"
)

// NodeID is the unique identifier of a node.
type NodeID string

// SessionID is the unique identifier of a session.
type SessionID string

// CircuitID is the unique identifier of a circuit evaluation.
type CircuitID string

// FHEParameters are the FHE parameters of a session, as instantiated from their
// literal representation (e.g., bgv.Parameters or ckks.Parameters).
type FHEParameters = rlwe.ParameterProvider

// FHEParametersLiteralProvider is the literal representation of a session's FHE
// parameters (e.g., bgv.ParametersLiteral or ckks.ParametersLiteral).
type FHEParametersLiteralProvider interface {
	GetRLWEParametersLiteral() rlwe.ParametersLiteral
}

// Parameters describes a Helium session: the nodes taking part in it, the FHE
// parameters, the threshold of the access structure and the common random seed.
// It is the same for all the nodes of a session.
type Parameters struct {
	ID            SessionID
	Nodes         []NodeID
	FHEParameters FHEParametersLiteralProvider
	Threshold     int
	ShamirPks     map[NodeID]drlwe.ShamirPublicPoint
	PublicSeed    []byte
}

func (p *Parameters) UnmarshalJSON(data []byte) error {
	type Alias Parameters
	aux := &struct {
		FHEParameters json.RawMessage
		*Alias
	}{
		Alias: (*Alias)(p),
	}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	var bgvParams bgv.ParametersLiteral
	var ckksParams ckks.ParametersLiteral
	switch {
	case json.Unmarshal([]byte(aux.FHEParameters), &bgvParams) == nil:
		p.FHEParameters = bgvParams
	case json.Unmarshal([]byte(aux.FHEParameters), &ckksParams) == nil:
		p.FHEParameters = ckksParams
	default:
		return fmt.Errorf("could not unmarshal FHE parameters")
	}
	return nil
}

// Secrets holds the secret material of a node for a session.
type Secrets struct {
	PrivateSeed        []byte
	ThresholdSecretKey *drlwe.ShamirSecretShare
}

// SecretProvider is a function that returns the secrets of a node for a session,
// given the session ID and the node ID.
type SecretProvider func(SessionID, NodeID) (*Secrets, error)

// Session is the state of a node within a session: the session parameters, the
// node's own identity and, for session nodes, its secret-key material.
type Session struct {
	Parameters
	Secrets
	NodeID NodeID

	Params FHEParameters

	secretKey *rlwe.SecretKey
	rlkEphSk  *rlwe.SecretKey
}

// NewSession creates the session state of node nodeID for the given parameters.
// Session nodes must provide their secrets; the helper node passes nil.
func NewSession(nodeID NodeID, sessParams Parameters, secrets *Secrets) (sess *Session, err error) {
	sess = new(Session)
	sess.NodeID = nodeID

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

	sess.ShamirPks = make(map[NodeID]drlwe.ShamirPublicPoint, len(sessParams.ShamirPks))
	needShamirPks := sess.Parameters.Threshold < len(sess.Parameters.Nodes)
	for _, nid := range sess.Nodes {
		var has bool
		if sess.ShamirPks[nid], has = sessParams.ShamirPks[nid]; !has && needShamirPks {
			return nil, fmt.Errorf("invalid session parameters: missing Shamir public point for node %s", nid)
		}
	}

	sess.FHEParameters = sessParams.FHEParameters
	sess.Params, err = NewFHEParameters(sessParams.FHEParameters)
	if err != nil {
		return nil, fmt.Errorf("could not create session parameters: %s", err)
	}

	// node re-generates its secret-key material for the session
	if utils.NewSet(sessParams.Nodes).Contains(nodeID) {

		if secrets == nil || len(secrets.PrivateSeed) == 0 {
			return nil, fmt.Errorf("session nodes must specify session secrets")
		}

		sess.PrivateSeed = slices.Clone(secrets.PrivateSeed)

		sessPrng, err := sampling.NewKeyedPRNG(secrets.PrivateSeed)
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
			if secrets.ThresholdSecretKey == nil {
				return nil, fmt.Errorf("session nodes must specify threshold secret key when session threshold is less than the number of nodes")
			}
			sess.ThresholdSecretKey = &drlwe.ShamirSecretShare{Poly: *secrets.ThresholdSecretKey.CopyNew()} // TODO: add copy method to Lattigo
		}
	}

	return sess, nil
}

// NewFHEParameters instantiates the FHE parameters from their literal representation.
func NewFHEParameters(paramsLit FHEParametersLiteralProvider) (params FHEParameters, err error) {
	switch pl := paramsLit.(type) {
	case bgv.ParametersLiteral:
		params, err = bgv.NewParametersFromLiteral(pl)
	case ckks.ParametersLiteral:
		params, err = ckks.NewParametersFromLiteral(pl)
	default:
		err = fmt.Errorf("unknown FHE parameters type")
	}
	return
}

// NewSecretKeyFromSeed derives a node's session secret key from its private seed. It
// is the same key that NewSession derives for a node holding these secrets, exposed
// for the generation of the threshold secret shares.
func NewSecretKeyFromSeed(params FHEParameters, seed []byte) (*rlwe.SecretKey, error) {
	prng, err := sampling.NewKeyedPRNG(seed)
	if err != nil {
		return nil, err
	}
	return genSecretKey(params, prng)
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

// GetSecretKeyForGroup returns the node's additive share of the ideal secret key
// for the given group of parties.
func (sess *Session) GetSecretKeyForGroup(parties []NodeID) (sk *rlwe.SecretKey, err error) {
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

// GetSecretKey returns the node's secret key for the session.
func (sess *Session) GetSecretKey() (*rlwe.SecretKey, error) {
	if sess.secretKey == nil {
		return nil, fmt.Errorf("node has no secret-key in the session")
	}
	return sess.secretKey, nil
}

// GetRLKEphemeralSecretKey returns the node's ephemeral secret key for the
// relinearization-key generation protocol.
func (sess *Session) GetRLKEphemeralSecretKey() (*rlwe.SecretKey, error) {
	if sess.rlkEphSk == nil {
		return nil, fmt.Errorf("node has no rlk ephemeral secret-key in the session")
	}
	return sess.rlkEphSk, nil
}

// GetThresholdSecretKey returns the node's share of the threshold secret key.
func (sess *Session) GetThresholdSecretKey() (*drlwe.ShamirSecretShare, error) {
	if sess.ThresholdSecretKey == nil {
		return nil, fmt.Errorf("node has no threshold secret-key in the session")
	}
	return sess.ThresholdSecretKey, nil
}

// GetShamirPublicPoints returns the Shamir public points of the session nodes.
func (sess *Session) GetShamirPublicPoints() map[NodeID]drlwe.ShamirPublicPoint {
	spts := make(map[NodeID]drlwe.ShamirPublicPoint, len(sess.ShamirPks))
	for p, spt := range sess.ShamirPks {
		spts[p] = spt
	}
	return spts
}

// GetShamirPublicPointsList returns the Shamir public points of the session nodes as a list.
func (sess *Session) GetShamirPublicPointsList() []drlwe.ShamirPublicPoint {
	spts := make([]drlwe.ShamirPublicPoint, 0, len(sess.ShamirPks))
	for _, spt := range sess.ShamirPks {
		spts = append(spts, spt)
	}
	return spts
}

// Contains returns whether nodeID is a session node.
func (sess *Session) Contains(nodeID NodeID) bool {
	return utils.NewSet(sess.Nodes).Contains(nodeID)
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

// NewCiphertext returns a new, zero ciphertext for the given parameters, degree and
// level (the maximum level if none is given).
func NewCiphertext(p FHEParameters, degree int, level ...int) *rlwe.Ciphertext {
	switch pp := p.(type) {
	case bgv.Parameters:
		llevel := pp.MaxLevel()
		if len(level) > 0 {
			llevel = level[0]
		}
		return bgv.NewCiphertext(pp, degree, llevel)
	case ckks.Parameters:
		llevel := pp.MaxLevel()
		if len(level) > 0 {
			llevel = level[0]
		}
		return ckks.NewCiphertext(pp, degree, llevel)
	default:
		panic(fmt.Errorf("unknown FHE parameters type"))
	}
}

// ObjectStoreConfig is the configuration of a node's persistent object store.
type ObjectStoreConfig = objectstore.Config
