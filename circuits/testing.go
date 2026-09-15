package circuits

import (
	"context"
	"fmt"
	"sync"

	"github.com/ChristianMct/helium"
)

// TestTransport is an in-memory OperandTransport connecting a set of Runners running in
// the same process. Inputs are routed to the evaluator's runner, and operand
// queries to the owner's runner.
type TestTransport struct {
	mu      sync.Mutex
	runners map[helium.NodeID]*Runner
}

// NewTestTransport creates a new, empty, TestTransport.
func NewTestTransport() *TestTransport {
	return &TestTransport{runners: make(map[helium.NodeID]*Runner)}
}

// AddRunner registers a runner as the endpoint for its node id.
func (t *TestTransport) AddRunner(r *Runner) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.runners[r.NodeID()] = r
}

// For returns the OperandTransport to be used by node nid.
func (t *TestTransport) For(nid helium.NodeID) OperandTransport {
	return &testNodeTransport{t: t, self: nid}
}

func (t *TestTransport) runner(nid helium.NodeID) (*Runner, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	r, has := t.runners[nid]
	if !has {
		return nil, fmt.Errorf("no runner for node %s", nid)
	}
	return r, nil
}

type testNodeTransport struct {
	t    *TestTransport
	self helium.NodeID
}

func (nt *testNodeTransport) PutOperand(ctx context.Context, cd helium.Descriptor, op helium.Operand) error {
	dst, err := nt.t.runner(cd.Evaluator)
	if err != nil {
		return err
	}
	return dst.HandleOperand(ctx, op)
}

func (nt *testNodeTransport) GetOperand(ctx context.Context, id helium.OperandID) (*helium.Operand, error) {
	src, err := nt.t.runner(id.NodeID())
	if err != nil {
		return nil, err
	}
	return src.GetOperand(ctx, id)
}
