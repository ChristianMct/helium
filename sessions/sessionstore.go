package sessions

import (
	"context"
	"fmt"
	"sync"
)

type Provider interface {
	GetSessionFromID(sessionID ID) (*Session, bool)
	GetSessionFromContext(ctx context.Context) (*Session, bool)
}

type Store struct {
	lock sync.RWMutex
	sess map[ID]*Session
}

func NewStore() *Store {
	ss := new(Store)
	ss.sess = make(map[ID]*Session)
	return ss
}

func (s *Store) NewRLWESession(sessParams Parameters, nodeID NodeID) (sess *Session, err error) {

	if _, exists := s.sess[sessParams.ID]; exists {
		return nil, fmt.Errorf("session id already exists: %s", sessParams.ID)
	}

	sess, err = NewSession(sessParams, nodeID)
	if err != nil {
		return nil, err
	}

	s.sess[sess.ID] = sess

	return sess, err
}

func (s *Store) GetSessionFromID(id ID) (*Session, bool) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	sess, ok := s.sess[id]
	return sess, ok
}
