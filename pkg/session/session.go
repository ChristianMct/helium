package pkg

import (
	"fmt"
	"log"

	"github.com/tuneinsight/lattigo/v3/rlwe"
	"github.com/tuneinsight/lattigo/v3/utils"

	"github.com/tuneinsight/lattigo/v3/drlwe"

	"sync"
)

type SessionID string

type ProtocolID string

type CircuitID string

type NodeID string

type NodeAddress string

func (na NodeAddress) String() string {
	return string(na)
}

type Session struct {
	*drlwe.Combiner
	*CiphertextStore

	ID SessionID
	//NodeAddress string
	NodeID NodeID
	Nodes  []NodeID

	T       int
	SPKS    map[NodeID]drlwe.ShamirPublicPoint
	tsk     *drlwe.ShamirSecretShare
	tskDone sync.Cond

	CRSKey []byte
	CRS    drlwe.CRS
	Params *rlwe.Parameters

	sk *rlwe.SecretKey
	*rlwe.PublicKey
	*rlwe.RelinearizationKey
	*rlwe.EvaluationKey

	mutex sync.RWMutex
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

func NewSession(params *rlwe.Parameters, sk *rlwe.SecretKey, crsKey []byte, nodeId NodeID, nodes []NodeID, t int, shamirPts map[NodeID]drlwe.ShamirPublicPoint, sessionID SessionID) (sess *Session, err error) {

	sess = new(Session)
	sess.ID = SessionID(sessionID)
	//sess.NodeAddress = nodeId
	sess.NodeID = NodeID(nodeId)
	sess.Nodes = nodes

	sess.Params = params

	sess.sk = sk
	sess.EvaluationKey = &rlwe.EvaluationKey{Rlk: rlwe.NewRelinKey(*params, 1), Rtks: rlwe.NewRotationKeySet(*params, []uint64{})}
	sess.RelinearizationKey = sess.EvaluationKey.Rlk
	sess.CRSKey = crsKey
	prng, err := utils.NewKeyedPRNG(sess.CRSKey)
	if err != nil {
		log.Fatal(err)
	}
	sess.CRS = prng

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

	sess.Combiner = drlwe.NewCombiner(*params, shamirPts[nodeId], spts, t)
	sess.CiphertextStore = NewCiphertextStore()

	return sess, err
}

func (s *SessionStore) NewRLWESession(params *rlwe.Parameters, sk *rlwe.SecretKey, crsKey []byte, nodeId NodeID, nodes []NodeID, t int, shamirPks map[NodeID]drlwe.ShamirPublicPoint, sessionID SessionID) (sess *Session, err error) {

	if _, exists := s.sessions[SessionID(sessionID)]; exists {
		return nil, fmt.Errorf("session id already exists: %s", sessionID)
	}

	sess, err = NewSession(params, sk, crsKey, nodeId, nodes, t, shamirPks, sessionID)

	s.sessions[sess.ID] = sess

	return
}

func (s *SessionStore) GetSessionFromID(id SessionID) (*Session, bool) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	sess, ok := s.sessions[id]
	return sess, ok
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

func (s *Session) SetTSK(tsk *drlwe.ShamirSecretShare) {
	s.tskDone.L.Lock()
	defer s.tskDone.L.Unlock()

	s.tsk = &drlwe.ShamirSecretShare{Poly: tsk.CopyNew()}
	s.tskDone.Broadcast()
}

func (s *Session) GetSecretKey() *rlwe.SecretKey {
	return s.sk
}

func (s *Session) SecretKeyForGroup(parties []NodeID) (sk *rlwe.SecretKey, err error) {
	switch {
	case len(parties) == len(s.Nodes):
		if s.sk == nil {
			return nil, fmt.Errorf("party has no secret-key in the session")
		}
		return s.sk, nil
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

func getParamsFromString(stringParams string) (rlwe.Parameters, error) {
	switch stringParams {
	case "TestPN12QP109":
		return rlwe.NewParametersFromLiteral(rlwe.TestPN12QP109)
	case "TestPN14QP438":
		return rlwe.NewParametersFromLiteral(rlwe.TestPN14QP438)
	case "TestPN13QP218":
		return rlwe.NewParametersFromLiteral(rlwe.TestPN13QP218)
	case "TestPN15QP880":
		return rlwe.NewParametersFromLiteral(rlwe.TestPN15QP880)
	default:
		return rlwe.Parameters{}, nil
	}
}
