package pkg

import (
	"context"
	"fmt"
	"slices"

	"github.com/ldsec/helium/pkg/objectstore"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v4/bgv"
	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/utils/sampling"
	"google.golang.org/grpc/metadata"

	"github.com/tuneinsight/lattigo/v4/drlwe"
)

type NodeInfo struct {
	NodeID
	NodeAddress
}

type NodesList []NodeInfo

func (nl NodesList) AddressOf(id NodeID) NodeAddress {
	for _, node := range nl {
		if node.NodeID == id {
			return node.NodeAddress
		}
	}
	return ""
}

func (nl NodesList) String() string {
	str := "[ "
	for _, node := range nl {
		str += fmt.Sprintf(`{ID: %s, Address: %s} `,
			node.NodeID, node.NodeAddress)
	}
	return str + "]"
}

type SessionID string

type ProtocolID string

type CircuitID string

type NodeID string

type NodeAddress string

type ctxKey string

var (
	ctxSessionID ctxKey = "session_id"
	ctxCircuitID ctxKey = "circuit_id"
)

func NewContext(sessID *SessionID, circID *CircuitID) context.Context {
	ctx := context.Background()
	if sessID != nil {
		ctx = context.WithValue(ctx, ctxSessionID, *sessID)
	}
	if circID != nil {
		ctx = AppendCircuitID(ctx, *circID)
	}
	return ctx
}

func NewOutgoingContext(senderID *NodeID, sessID *SessionID, circID *CircuitID) context.Context {
	md := metadata.New(nil)
	if senderID != nil {
		md.Append("sender_id", string(*senderID))
	}
	if sessID != nil {
		md.Append(string(ctxSessionID), string(*sessID))
	}
	if circID != nil {
		md.Append(string(ctxCircuitID), string(*circID))
	}
	return metadata.NewOutgoingContext(context.Background(), md)
}

func GetOutgoingContext(ctx context.Context, senderID NodeID) context.Context {
	md := metadata.New(nil)
	md.Append("sender_id", string(senderID))
	if sessID, hasSessID := SessionIDFromContext(ctx); hasSessID {
		md.Append(string(ctxSessionID), string(sessID))
	}
	if circID, hasCircID := CircuitIDFromContext(ctx); hasCircID {
		md.Append(string(ctxCircuitID), string(circID))
	}
	return metadata.NewOutgoingContext(ctx, md)
}

func GetContextFromIncomingContext(inctx context.Context) (ctx context.Context, err error) {

	sid := SessionIDFromIncomingContext(inctx)
	if len(sid) == 0 {
		return nil, fmt.Errorf("invalid incoming context: missing session id")
	}

	ctx = context.WithValue(inctx, ctxSessionID, sid)
	cid := CircuitIDFromIncomingContext(inctx)
	if len(cid) != 0 {
		ctx = context.WithValue(ctx, ctxCircuitID, cid)
	}
	return
}

func AppendCircuitID(ctx context.Context, circID CircuitID) context.Context {
	return context.WithValue(ctx, ctxCircuitID, circID)
}

func ValueFromIncomingContext(ctx context.Context, key string) string {
	md, hasMd := metadata.FromIncomingContext(ctx)
	if !hasMd {
		return ""
	}
	id := md.Get(key)
	if len(id) < 1 {
		return ""
	}
	return id[0]
}

func SenderIDFromIncomingContext(ctx context.Context) NodeID {
	return NodeID(ValueFromIncomingContext(ctx, "sender_id"))
}

func SessionIDFromIncomingContext(ctx context.Context) SessionID {
	return SessionID(ValueFromIncomingContext(ctx, string(ctxSessionID)))
}

func CircuitIDFromIncomingContext(ctx context.Context) CircuitID {
	return CircuitID(ValueFromIncomingContext(ctx, string(ctxCircuitID)))
}

func SessionIDFromContext(ctx context.Context) (SessionID, bool) {
	sessID, ok := ctx.Value(ctxSessionID).(SessionID)
	return sessID, ok
}

func CircuitIDFromContext(ctx context.Context) (CircuitID, bool) {
	circID, isValid := ctx.Value(ctxCircuitID).(CircuitID)
	return circID, isValid
}

func (na NodeAddress) String() string {
	return string(na)
}

func (pid ProtocolID) String() string {
	return string(pid)
}

// Session is the context of an MPC protocol execution.
type Session struct {
	SessionParameters
	NodeID NodeID
	Params bgv.Parameters

	//sessSecrets *SessionSecrets
	secretKey *rlwe.SecretKey
	rlkEphSk  *rlwe.SecretKey

	*CiphertextStore
	objectstore.ObjectStore
}

type SessionSecrets struct {
	PrivateSeed        []byte
	ThresholdSecretKey *drlwe.ShamirSecretShare
}

// SessionParameters contains data used to initialize a Session.
type SessionParameters struct {
	ID         SessionID
	Nodes      []NodeID
	RLWEParams bgv.ParametersLiteral
	Threshold  int
	ShamirPks  map[NodeID]drlwe.ShamirPublicPoint
	PublicSeed []byte
	*SessionSecrets
}

func NewSession(sessParams SessionParameters, nodeID NodeID, objStore objectstore.ObjectStore) (sess *Session, err error) {
	sess = new(Session)
	sess.NodeID = nodeID
	sess.ObjectStore = objStore

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
	for _, nid := range sess.Nodes {
		var has bool
		if sess.ShamirPks[nid], has = sessParams.ShamirPks[nid]; !has {
			return nil, fmt.Errorf("invalid session parameters: missing Shamir public point for node %s", nid)
		}
	}

	sess.Params, err = bgv.NewParametersFromLiteral(sessParams.RLWEParams)
	if err != nil {
		return nil, fmt.Errorf("could not create session parameters: %s", err)
	}

	// node re-generates its secret-key material for the session
	if utils.NewSet(sessParams.Nodes).Contains(nodeID) {

		if sessParams.SessionSecrets == nil || len(sessParams.SessionSecrets.PrivateSeed) == 0 {
			return nil, fmt.Errorf("session nodes must specify session secrets")
		}

		sess.SessionSecrets = new(SessionSecrets)
		sess.PrivateSeed = slices.Clone(sessParams.SessionSecrets.PrivateSeed)

		sessPrng, err := sampling.NewKeyedPRNG(sessParams.SessionSecrets.PrivateSeed)
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

	//sess.Combiner = drlwe.NewCombiner(*params, shamirPts[nodeID], spts, t)
	sess.CiphertextStore = NewCiphertextStore()

	return sess, nil
}

func genSecretKey(params rlwe.ParametersInterface, prng sampling.PRNG) (sk *rlwe.SecretKey, err error) {

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

// // GetCollectivePublicKey loads the collective public key from the ObjectStore.
// func (s *Session) GetCollectivePublicKey() (*rlwe.PublicKey, error) {
// 	cpk := new(rlwe.PublicKey)

// 	if err := s.ObjectStore.Load("CKG()", cpk); err != nil {
// 		return nil, fmt.Errorf("error while loading the collective public key: %w", err)
// 	}

// 	return cpk, nil
// }

// // SetCollectivePublicKey stores the collective public key into the ObjectStore.
// func (s *Session) SetCollectivePublicKey(cpk *rlwe.PublicKey) error {
// 	if err := s.ObjectStore.Store("CKG()", cpk); err != nil {
// 		return fmt.Errorf("error while storing the collective public key: %w", err)
// 	}

// 	return nil
// }

// // GetRelinearizationKey loads the relinearization key from the ObjectStore.
// func (s *Session) GetRelinearizationKey() (*rlwe.RelinearizationKey, error) {
// 	rlk := new(rlwe.RelinearizationKey)

// 	if err := s.ObjectStore.Load("RKG_2()", rlk); err != nil {
// 		return nil, fmt.Errorf("error while loading the relinearization key: %w", err)
// 	}

// 	return rlk, nil
// }

// // SetRelinearizationKey stores the relinearization key into the ObjectStore.
// func (s *Session) SetRelinearizationKey(rlk *rlwe.RelinearizationKey) error {
// 	if err := s.ObjectStore.Store("RKG_2()", rlk); err != nil {
// 		return fmt.Errorf("error while storing the relinearization key: %w", err)
// 	}

// 	return nil
// }

// // SetRotationKey loads the rotation key identified by the Galois element from the ObjectStore.
// func (s *Session) GetRotationKey(galEl uint64) (*rlwe.GaloisKey, error) {
// 	rtk := new(rlwe.GaloisKey)
// 	if err := s.ObjectStore.Load(fmt.Sprintf("RTG(GalEl=%d)", galEl), rtk); err != nil {
// 		return nil, fmt.Errorf("error while loading the rotation key with galEl %d: %w", galEl, err)
// 	}

// 	return rtk, nil
// }

// // SetRotationKey stores the rotation key identified by the Galois element into the ObjectStore.
// func (s *Session) SetRotationKey(rtk *rlwe.GaloisKey, galEl uint64) error {
// 	if err := s.ObjectStore.Store(fmt.Sprintf("RTG(GalEl=%d)", galEl), rtk); err != nil {
// 		return fmt.Errorf("error while storing the rotation key with galEl %d: %w", galEl, err)
// 	}

// 	return nil
// }

// func (s *Session) GetPublicKey() (*rlwe.PublicKey, error) {
// 	cpk := new(rlwe.PublicKey)

// 	if err := s.ObjectStore.Load("PK", cpk); err != nil {
// 		return nil, fmt.Errorf("error while loading the collective public key: %w", err)
// 	}

// 	return cpk, nil
// }

// func (s *Session) SetPublicKey(cpk *rlwe.PublicKey) error {
// 	if err := s.ObjectStore.Store("PK", cpk); err != nil {
// 		return fmt.Errorf("error while storing the collective public key: %w", err)
// 	}

// 	return nil
// }

// // GetOutputPkForNode loads the output public key for a node from the ObjectStore.
// func (s *Session) GetOutputPkForNode(nid NodeID) (pk *rlwe.PublicKey, exists error) {
// 	outputPk := rlwe.NewPublicKey(s.Params)

// 	if err := s.ObjectStore.Load(fmt.Sprintf("PK(Sender=%s)", nid), outputPk); err != nil {
// 		return nil, fmt.Errorf("error while loading the output public key of node %s: %w", nid, err)
// 	}

// 	return outputPk, nil
// }

// // SetOutputPkForNode stores the output public key for a node into the ObjectStore.
// func (s *Session) SetOutputPkForNode(nid NodeID, outputPk *rlwe.PublicKey) error {
// 	if err := s.ObjectStore.Store(fmt.Sprintf("PK(Sender=%s)", nid), outputPk); err != nil {
// 		return fmt.Errorf("error while storing the output public key of node %s: %w", nid, err)
// 	}

// 	return nil
// }

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
		drlwe.NewCombiner(sess.Params.Parameters,
			sess.GetShamirPublicPoints()[sess.NodeID],
			sess.GetShamirPublicPointsList(),
			sess.Threshold).GenAdditiveShare(spks, sess.ShamirPks[sess.NodeID], *sess.ThresholdSecretKey, sk)
		return sk, nil
	default:
		return nil, fmt.Errorf("group of size %d is not enough participants to reconstruct", len(parties))
	}
}

// // GetOutputSk loads the output secret key of this node from the ObjectStore.
// func (s *Session) GetOutputSk() (*rlwe.SecretKey, error) {
// 	outputSk := rlwe.NewSecretKey(*s.Params)

// 	if err := s.ObjectStore.Load("outputSK", outputSk); err != nil {
// 		return nil, fmt.Errorf("error while loading the output secret key: %w", err)
// 	}

// 	return outputSk, nil
// }

// // SetOuputSk stores the output secret key of this node into the ObjectStore.
// func (s *Session) SetOuputSk(outputSk *rlwe.SecretKey) error {
// 	if err := s.ObjectStore.Store("outputSK", outputSk); err != nil {
// 		return fmt.Errorf("error while storing the output secret key: %w", err)
// 	}

// 	return nil
// }

// GetSecretKey loads the secret key from the ObjectStore.
func (s *Session) GetSecretKey() (*rlwe.SecretKey, error) {
	if s.secretKey == nil {
		return nil, fmt.Errorf("node has no secret-key in the session")
	}
	return s.secretKey, nil
}

func (s *Session) GetRLKEphemeralSecretKey() (*rlwe.SecretKey, error) {
	if s.rlkEphSk == nil {
		return nil, fmt.Errorf("node has no rlk ephemeral secret-key in the session")
	}
	return s.rlkEphSk, nil
}

// GetThresholdSecretKey loads the secret key from the ObjectStore.
func (s *Session) GetThresholdSecretKey() (*drlwe.ShamirSecretShare, error) {
	if s.ThresholdSecretKey == nil {
		return nil, fmt.Errorf("node has no threshold secret-key in the session")
	}
	return s.ThresholdSecretKey, nil
}

// // SetSecretKey stores the secret key into the ObjectStore.
// func (s *Session) SetSecretKey(sk *rlwe.SecretKey) error {
// 	if err := s.ObjectStore.Store("sessionSK", sk); err != nil {
// 		return fmt.Errorf("error while storing the session secret key: %w", err)
// 	}
// 	return nil
// }

// // SetThresholdSecretKey stores the secret key into the ObjectStore.
// func (s *Session) SetThresholdSecretKey(tsk *drlwe.ShamirSecretShare) error {
// 	if err := s.ObjectStore.Store("sessionThresholdSK", tsk); err != nil {
// 		return fmt.Errorf("error while storing the session threshold secret key: %w", err)
// 	}
// 	return nil
// }

// func (s *Session) SetRLKEphemeralSecretKey(sk *rlwe.SecretKey) error {
// 	if err := s.ObjectStore.Store("rlkEphSK", sk); err != nil {
// 		return fmt.Errorf("error while storing the session rlk ephemeral  secret key: %w", err)
// 	}
// 	return nil
// }

func (s *Session) GetShamirPublicPoints() map[NodeID]drlwe.ShamirPublicPoint {
	spts := make(map[NodeID]drlwe.ShamirPublicPoint, len(s.ShamirPks))
	for p, spt := range s.ShamirPks {
		spts[p] = spt
	}
	return spts
}

func (s *Session) GetShamirPublicPointsList() []drlwe.ShamirPublicPoint {
	spts := make([]drlwe.ShamirPublicPoint, 0, len(s.ShamirPks))
	for _, spt := range s.ShamirPks {
		spts = append(spts, spt)
	}
	return spts
}

func (s *Session) Contains(nodeID NodeID) bool {
	return utils.NewSet(s.Nodes).Contains(nodeID)
}

func (s *Session) GetSessionFromID(sessionID SessionID) (*Session, bool) {
	if s.ID == sessionID {
		return s, true
	}
	return nil, false
}

func (s *Session) GetSessionFromContext(ctx context.Context) (*Session, bool) {
	sessID, has := SessionIDFromContext(ctx)
	if !has {
		return nil, false
	}
	return s.GetSessionFromID(sessID)
}

func (s *Session) GetSessionFromIncomingContext(ctx context.Context) (*Session, bool) {
	sessID := SessionIDFromIncomingContext(ctx) // TODO should have same interface as GetSessionFromContext
	return s.GetSessionFromID(sessID)
}

func (s *Session) String() string {
	return fmt.Sprintf(`
	{
		ID: %s,
		NodeID: %s,
		Nodes: %v,
		T: %d,
		CRSKey: %v,
	}`, s.ID, s.NodeID, s.Nodes, s.Threshold, s.PublicSeed)
}
