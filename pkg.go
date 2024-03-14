// Package helium provides the main types and interfaces for the Helium framework.
package helium

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/tuneinsight/lattigo/v4/rlwe"
)

// NodeID is the unique identifier of a node.
type NodeID string

// SessionID is the unique identifier of a session.
type SessionID string

// CircuitID is the unique identifier of a running circuit.
type CircuitID string

type CiphertextID string

// NodeAddress is the network address of a node.
type NodeAddress string

// NodeInfo contains the unique identifier and the network address of a node.
type NodeInfo struct {
	NodeID
	NodeAddress
}

// NodesList is a list of known nodes in the network. It must contains all nodes
// for a given application, including the current node. It does not need to contain
// an address for all nodes, except for the helper node.
type NodesList []NodeInfo

// AddressOf returns the network address of the node with the given ID. Returns
// an empty string if the node is not found in the list.
func (nl NodesList) AddressOf(id NodeID) NodeAddress {
	for _, node := range nl {
		if node.NodeID == id {
			return node.NodeAddress
		}
	}
	return ""
}

// String returns a string representation of the list of nodes.
func (nl NodesList) String() string {
	str := "[ "
	for _, node := range nl {
		str += fmt.Sprintf(`{ID: %s, Address: %s} `,
			node.NodeID, node.NodeAddress)
	}
	return str + "]"
}

type ctxKey string

var (
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

// String returns a string representation of the node address.
func (na NodeAddress) String() string {
	return string(na)
}

// CiphertextType is an enumerated type for the types of ciphertexts.
type CiphertextType int

const (
	// Unspecified is the default value for the type of a ciphertext.
	Unspecified CiphertextType = iota
	// BFV is the type of a ciphertext in the BFV scheme.
	BFV
	// BGV is the type of a ciphertext in the BGV scheme.
	BGV
	// CKKS is the type of a ciphertext in the CKKS scheme.
	CKKS
	// RGSW is the type of a ciphertext in the RGSW scheme.
	RGSW
)

var typeToString = [...]string{"Unspecified", "BFV", "BGV", "CKKS", "RGSW"}

// String returns a string representation of the ciphertext type.
func (ctt CiphertextType) String() string {
	if ctt < 0 || int(ctt) > len(typeToString) {
		return "invalid"
	}
	return typeToString[ctt]
}

// CiphertextMetadata contains information on ciphertexts.
// In the current bgv-specific implementation, the type is not used.
type CiphertextMetadata struct {
	ID   CiphertextID
	Type CiphertextType
}

// URL defines a URL format to serve as ciphertext identifier for
// the Helium framwork.
type URL url.URL

// ParseURL parses a string into a helium URL.
func ParseURL(s string) (*URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	return (*URL)(u), nil
}

func (u *URL) CiphertextBaseID() CiphertextID {
	return CiphertextID(path.Base(u.Path))
}

func (u *URL) CiphertextID() CiphertextID {
	return CiphertextID(u.String())
}

// NodeID returns the host part of the URL as a NodeID.
func (u *URL) NodeID() NodeID {
	return NodeID(u.Host)
}

// CircuitID returns the circuit id part of the URL, if any.
// Returns the empty string if no circuit id is present.
func (u *URL) CircuitID() string {
	if dir, _ := path.Split(u.Path); len(dir) > 0 { // ctid belongs to a circuit
		return strings.SplitN(strings.Trim(dir, "/"), "/", 2)[0]
	}
	return ""
}

// String returns the string representation of the URL.
func (u *URL) String() string {
	return (*url.URL)(u).String()
}

// Ciphertext is a type for ciphertext within the helium framework.
type Ciphertext struct {
	rlwe.Ciphertext
	CiphertextMetadata
}
