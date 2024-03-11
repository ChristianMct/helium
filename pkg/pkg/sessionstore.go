package pkg

import (
	"context"
	"fmt"
	"sync"

	"github.com/ldsec/helium/pkg/objectstore"
)

type SessionProvider interface {
	GetSessionFromID(sessionID SessionID) (*Session, bool)
	GetSessionFromContext(ctx context.Context) (*Session, bool)
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

func (s *SessionStore) NewRLWESession(sessParams SessionParameters, nodeID NodeID, objStore objectstore.ObjectStore) (sess *Session, err error) {

	if _, exists := s.sessions[sessParams.ID]; exists {
		return nil, fmt.Errorf("session id already exists: %s", sessParams.ID)
	}

	sess, err = NewSession(sessParams, nodeID, objStore)
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
