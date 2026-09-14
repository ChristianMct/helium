package circuits

import (
	"context"
	"fmt"
	"sync"

	"github.com/ChristianMct/helium"
)

// TestEngineTransport is an in-memory OperandTransport connecting a set of Engines running in
// the same process. Inputs are routed to the evaluator's engine, and operand
// queries to the owner's engine.
type TestEngineTransport struct {
	mu      sync.Mutex
	engines map[helium.NodeID]*Engine
}

// NewTestEngineTransport creates a new, empty, TestEngineTransport.
func NewTestEngineTransport() *TestEngineTransport {
	return &TestEngineTransport{engines: make(map[helium.NodeID]*Engine)}
}

// AddEngine registers an engine as the endpoint for its node id.
func (t *TestEngineTransport) AddEngine(e *Engine) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.engines[e.NodeID()] = e
}

// For returns the OperandTransport to be used by node nid.
func (t *TestEngineTransport) For(nid helium.NodeID) OperandTransport {
	return &testNodeTransport{t: t, self: nid}
}

func (t *TestEngineTransport) engine(nid helium.NodeID) (*Engine, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, has := t.engines[nid]
	if !has {
		return nil, fmt.Errorf("no engine for node %s", nid)
	}
	return e, nil
}

type testNodeTransport struct {
	t    *TestEngineTransport
	self helium.NodeID
}

func (nt *testNodeTransport) PutOperand(ctx context.Context, cd helium.Descriptor, op helium.Operand) error {
	dst, err := nt.t.engine(cd.Evaluator)
	if err != nil {
		return err
	}
	return dst.HandleOperand(ctx, op)
}

func (nt *testNodeTransport) GetOperand(ctx context.Context, id helium.OperandID) (*helium.Operand, error) {
	src, err := nt.t.engine(id.NodeID())
	if err != nil {
		return nil, err
	}
	return src.GetOperand(ctx, id)
}
