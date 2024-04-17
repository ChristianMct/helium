package session

import "context"

type ctxKey string

var (
	// CtxNodeID is the context key for the node ID.
	CtxNodeID ctxKey = "node_id"
	// CtxSessionID is the context key for the session ID.
	// Helium contexts must always have a session id.
	CtxSessionID ctxKey = "session_id"
	// CtxCircuitID is the context key for the circuit ID.
	// The circuit ID is optional and is only present in the context
	// of a circuit execution.
	CtxCircuitID ctxKey = "circuit_id"
)

// NewContext returns a new context derived from ctx with the given session and circuit IDs.
func NewContext(ctx context.Context, sessID SessionID, circID ...CircuitID) context.Context {
	ctx = context.WithValue(ctx, CtxSessionID, sessID)
	if len(circID) != 0 {
		ctx = ContextWithCircuitID(ctx, circID[0])
	}
	return ctx
}

// NewBackgroundContext returns a new context derived from context.Background with
// the given session and circuit IDs.
func NewBackgroundContext(sessID SessionID, circID ...CircuitID) context.Context {
	return NewContext(context.Background(), sessID, circID...)
}

// ContextWithCircuitID returns a new context derived from ctx with the given session ID.
func ContextWithCircuitID(ctx context.Context, circID CircuitID) context.Context {
	return context.WithValue(ctx, CtxCircuitID, circID)
}

// ContextWithNodeID returns a new context derived from ctx with the given node ID.
func ContextWithNodeID(ctx context.Context, nodeID NodeID) context.Context {
	return context.WithValue(ctx, CtxNodeID, nodeID)
}

// NodeIDFromContext returns the node ID from the context.
func NodeIDFromContext(ctx context.Context) (NodeID, bool) {
	nid, ok := ctx.Value(CtxNodeID).(NodeID)
	return nid, ok
}

// SessionIDFromContext returns the session ID from the context.
func SessionIDFromContext(ctx context.Context) (SessionID, bool) {
	sessID, ok := ctx.Value(CtxSessionID).(SessionID)
	return sessID, ok
}

// CircuitIDFromContext returns the circuit ID from the context, if present.
func CircuitIDFromContext(ctx context.Context) (CircuitID, bool) {
	circID, isPresent := ctx.Value(CtxCircuitID).(CircuitID)
	return circID, isPresent
}
