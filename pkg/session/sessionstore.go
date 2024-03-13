package session

import (
	"context"
	"fmt"
	"sync"

	"github.com/ldsec/helium/pkg"
)

type SessionProvider interface {
	GetSessionFromID(sessionID pkg.SessionID) (*Session, bool)
	GetSessionFromContext(ctx context.Context) (*Session, bool)
}

type SessionStore struct {
	lock     sync.RWMutex
	sessions map[pkg.SessionID]*Session
}

func NewSessionStore() *SessionStore {
	ss := new(SessionStore)
	ss.sessions = make(map[pkg.SessionID]*Session)
	return ss
}

func (s *SessionStore) NewRLWESession(sessParams Parameters, nodeID pkg.NodeID) (sess *Session, err error) {

	if _, exists := s.sessions[sessParams.ID]; exists {
		return nil, fmt.Errorf("session id already exists: %s", sessParams.ID)
	}

	sess, err = NewSession(sessParams, nodeID)
	if err != nil {
		return nil, err
	}

	s.sessions[sess.ID] = sess

	return sess, err
}

func (s *SessionStore) GetSessionFromID(id pkg.SessionID) (*Session, bool) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	sess, ok := s.sessions[id]
	return sess, ok
}
