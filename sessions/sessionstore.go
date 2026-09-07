package sessions

import "context"

// Provider is an interface for retrieving sessions. It is implemented by *Session
// for the single-session case.
type Provider interface {
	GetSessionFromID(sessionID ID) (*Session, bool)
	GetSessionFromContext(ctx context.Context) (*Session, bool)
}
