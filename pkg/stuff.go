package pkg

import (
	"context"
	"fmt"
)

// NodeID is the unique identifier of a node.
type NodeID string

// SessionID is the unique identifier of a session.
type SessionID string

type CircuitID string

type NodeAddress string

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

type CtxKey string

var (
	CtxSessionID CtxKey = "session_id"
	CtxCircuitID CtxKey = "circuit_id"
)

func NewContext(sessID *SessionID, circID *CircuitID) context.Context {
	ctx := context.Background()
	if sessID != nil {
		ctx = context.WithValue(ctx, CtxSessionID, *sessID)
	}
	if circID != nil {
		ctx = AppendCircuitID(ctx, *circID)
	}
	return ctx
}

func AppendCircuitID(ctx context.Context, circID CircuitID) context.Context {
	return context.WithValue(ctx, CtxCircuitID, circID)
}

func SessionIDFromContext(ctx context.Context) (SessionID, bool) {
	sessID, ok := ctx.Value(CtxSessionID).(SessionID)
	return sessID, ok
}

func CircuitIDFromContext(ctx context.Context) (CircuitID, bool) {
	circID, isValid := ctx.Value(CtxCircuitID).(CircuitID)
	return circID, isValid
}

func (na NodeAddress) String() string {
	return string(na)
}
