package pkg

import (
	"context"
	"fmt"
	"log"
	"math/rand"

	"github.com/ldsec/helium/pkg/session/objectstore"
	"github.com/ldsec/helium/pkg/session/objectstore/badgerobjectstore"
	"github.com/ldsec/helium/pkg/session/objectstore/memobjectstore"
	"github.com/ldsec/helium/pkg/session/objectstore/nullobjectstore"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"google.golang.org/grpc/metadata"

	"github.com/tuneinsight/lattigo/v4/drlwe"
	lattigoUtils "github.com/tuneinsight/lattigo/v4/utils"

	"sync"
)

type NodesList []struct {
	NodeID
	NodeAddress
	DelegateID NodeID
}

func (nl NodesList) String() string {
	str := "[ "
	for _, node := range nl {
		str += fmt.Sprintf(`{ ID: %s, Address: %s, DelegateID: %s } `,
			node.NodeID, node.NodeAddress, node.DelegateID)
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

// Session is the context of an MPC protocol execution.
type Session struct {
	*drlwe.Combiner
	*CiphertextStore

	objectstore.ObjectStore

	ID     SessionID
	NodeID NodeID
	Nodes  []NodeID

	T       int
	SPKS    map[NodeID]drlwe.ShamirPublicPoint
	tsk     *drlwe.ShamirSecretShare
	tskDone sync.Cond

	CRSKey []byte
	Params *rlwe.Parameters

	Sk *rlwe.SecretKey
	*rlwe.PublicKey
	*rlwe.RelinearizationKey
	*rlwe.EvaluationKey

	mutex sync.RWMutex
}

// SessionParameters contains data used to initialize a Session.
type SessionParameters struct {
	ID         SessionID
	RLWEParams rlwe.ParametersLiteral
	T          int
	Nodes      []NodeID
	ShamirPks  map[NodeID]drlwe.ShamirPublicPoint
	CRSKey     []byte

	ObjectStoreConfig objectstore.Config
}

type SessionProvider interface {
	GetSessionFromID(sessionID SessionID) (*Session, bool)
	GetSessionFromContext(ctx context.Context) (*Session, bool)
	GetSessionFromIncomingContext(ctx context.Context) (*Session, bool)
}

type SessionStore struct {
	lock     sync.RWMutex
	sessions map[SessionID]*Session
}

func NewSessionStore() *SessionStore {
	ss := new(SessionStore)
	ss.sessions = make(map[SessionID]*Session)
	return ss
}

func NewSession(sessParams *SessionParameters, params *rlwe.Parameters, sk *rlwe.SecretKey, crsKey []byte, nodeID NodeID, nodes []NodeID, t int, shamirPts map[NodeID]drlwe.ShamirPublicPoint, sessionID SessionID) (sess *Session, err error) {

	sess = new(Session)
	sess.ID = sessionID
	sess.NodeID = nodeID
	sess.Nodes = nodes

	sess.Params = params

	sess.Sk = sk
	sess.EvaluationKey = &rlwe.EvaluationKey{Rlk: rlwe.NewRelinearizationKey(*params, 1), Rtks: rlwe.NewRotationKeySet(*params, []uint64{})}
	sess.RelinearizationKey = sess.EvaluationKey.Rlk
	sess.CRSKey = crsKey

	sess.T = t
	sess.SPKS = make(map[NodeID]drlwe.ShamirPublicPoint, len(shamirPts))
	for id, spk := range shamirPts {
		sess.SPKS[id] = spk
	}
	spts := make([]drlwe.ShamirPublicPoint, 0, len(shamirPts))
	for _, pt := range shamirPts {
		spts = append(spts, pt)
	}

	sess.tskDone = *sync.NewCond(&sync.Mutex{})

	sess.Combiner = drlwe.NewCombiner(*params, shamirPts[nodeID], spts, t)
	sess.CiphertextStore = NewCiphertextStore()

	switch sessParams.ObjectStoreConfig.BackendName {
	case "null":
		sess.ObjectStore = nullobjectstore.NewObjectStore()
		break

	case "mem":
		sess.ObjectStore = memobjectstore.NewObjectStore()
		break

	case "badgerdb":
		// TODO remove hardcoded manipulation of DB path.
		sessParams.ObjectStoreConfig.DBPath += string(sess.NodeID)
		// END TODO.

		sess.ObjectStore, err = badgerobjectstore.NewObjectStore(&sessParams.ObjectStoreConfig)
		if err != nil {
			return nil, err
		}
		break

	// use in-memory backend as default case.
	default:
		log.Printf("Node %s | using default ObjectStore backend for session creation\n", sess.NodeID)
		sess.ObjectStore = memobjectstore.NewObjectStore()
		break
	}

	return sess, err
}

func (s *SessionStore) NewRLWESession(sessParams *SessionParameters, params *rlwe.Parameters, sk *rlwe.SecretKey, crsKey []byte, nodeID NodeID, nodes []NodeID, t int, shamirPks map[NodeID]drlwe.ShamirPublicPoint, sessionID SessionID) (sess *Session, err error) {

	if _, exists := s.sessions[sessionID]; exists {
		return nil, fmt.Errorf("session id already exists: %s", sessionID)
	}

	sess, err = NewSession(sessParams, params, sk, crsKey, nodeID, nodes, t, shamirPks, sessionID)
	if err != nil {
		return nil, err
	}

	s.sessions[sess.ID] = sess

	return sess, err
}

func (s *SessionStore) GetSessionFromID(id SessionID) (*Session, bool) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	sess, ok := s.sessions[id]
	return sess, ok
}

// Close releases the resources allocated all the sessions in the SessionStore.
func (s *SessionStore) Close() error {
	for _, session := range s.sessions {
		err := session.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Session) GetRelinKey() ([]byte, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	relin, err := s.RelinearizationKey.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return relin, nil
}

func (s *Session) SetRotationKey(galEl uint64, swk *rlwe.SwitchingKey) error {
	s.mutex.Lock()
	s.EvaluationKey.Rtks.Keys[galEl] = swk
	s.mutex.Unlock()
	return nil
}

func (s *Session) SetTSK(tsk *drlwe.ShamirSecretShare) {
	s.tskDone.L.Lock()
	defer s.tskDone.L.Unlock()

	s.tsk = &drlwe.ShamirSecretShare{Poly: tsk.CopyNew()}
	s.tskDone.Broadcast()
}

func (s *Session) GetSecretKey() *rlwe.SecretKey {
	return s.Sk
}

func (s *Session) HasTSK() bool {
	s.tskDone.L.Lock()
	defer s.tskDone.L.Unlock()
	return s.tsk != nil
}

func (s *Session) SecretKeyForGroup(parties []NodeID) (sk *rlwe.SecretKey, err error) {
	switch {
	case len(parties) == len(s.Nodes):
		if s.Sk == nil {
			return nil, fmt.Errorf("party has no secret-key in the session")
		}
		return s.Sk, nil
	case len(parties) >= s.T:
		s.tskDone.L.Lock() // TODO might be overkill as condition is irreversible
		for s.tsk == nil {
			s.tskDone.Wait()
		}
		sk = rlwe.NewSecretKey(*s.Params)
		spks := make([]drlwe.ShamirPublicPoint, len(parties))
		for i, pid := range parties {
			spks[i] = s.SPKS[pid]
		}
		s.Combiner.GenAdditiveShare(spks, s.SPKS[s.NodeID], s.tsk, sk)
		s.tskDone.L.Unlock()
		return sk, nil
	default:
		return nil, fmt.Errorf("not enough participants to reconstruct")
	}
}

func (s *Session) GetCRSForProtocol(pid ProtocolID) drlwe.CRS {
	crsKey := make([]byte, 0, len(s.CRSKey)+len(pid))
	crsKey = append(crsKey, s.CRSKey...)
	crsKey = append(crsKey, []byte(pid)...)
	prng, err := lattigoUtils.NewKeyedPRNG(crsKey)
	if err != nil {
		log.Fatal(err)
	}
	return prng
}

// StoreOuputSk stores the output secret key in the ObjectStore.
func (s *Session) StoreOuputSk(outputSk *rlwe.SecretKey) error {
	if err := s.ObjectStore.Store("outputSk", outputSk); err != nil {
		return fmt.Errorf("error while storing the output secret key: %w", err)
	}

	return nil
}

// OutputSk loads the output secret key from the ObjectStore.
func (s *Session) OutputSk() (*rlwe.SecretKey, error) {
	outputSk := rlwe.NewSecretKey(*s.Params)

	if err := s.ObjectStore.Load("outputSk", outputSk); err != nil {
		return nil, fmt.Errorf("error while loading the output secret key: %w", err)
	}

	return outputSk, nil
}

// StoreOutputPkForNode stores the output public key for a node in the ObjectStore.
func (s *Session) StoreOutputPkForNode(nid NodeID, outputPk *rlwe.PublicKey) error {
	if err := s.ObjectStore.Store("outputPk", outputPk); err != nil {
		return fmt.Errorf("error while storing the output public key: %w", err)
	}

	return nil
}

// GetOutputPkForNode load the output public key for a node from the ObjectStore.
func (s *Session) GetOutputPkForNode(nid NodeID) (pk *rlwe.PublicKey, exists error) {
	outputPk := rlwe.NewPublicKey(*s.Params)

	if err := s.ObjectStore.Load("outputPk", outputPk); err != nil {
		return nil, fmt.Errorf("error while loading the output public key: %w", err)
	}

	return outputPk, nil
}

func (s *Session) Contains(nodeID NodeID) bool {
	return utils.NewSet(s.Nodes).Contains(nodeID)
}

func GetRandomClientSlice(t int, nodes []NodeID) []NodeID {
	cid := make([]NodeID, len(nodes))
	copy(cid, nodes)
	rand.Shuffle(len(cid), func(i, j int) {
		cid[i], cid[j] = cid[j], cid[i]
	})
	return cid[:t]
}

func (s *Session) String() string {
	return fmt.Sprintf(`
	{
		ID: %s,
		NodeID: %s,
		Nodes: %v,
		T: %d,
		CRSKey: %v,
	}`, s.ID, s.NodeID, s.Nodes, s.T, s.CRSKey)
}
