package protocols

import (
	"context"
	"fmt"
	"sync"

	"github.com/ChristianMct/helium"
)

// TestTransport is an in-memory ShareTransport connecting a set of Runners
// running in the same process. Shares and queries are routed to the runner of
// the protocol's aggregator. Shares sent by a given node can be held
// back with GateShares, to simulate slow or failing participants.
type TestTransport struct {
	mu      sync.Mutex
	runners map[helium.NodeID]*Runner
	gates   map[helium.NodeID]chan struct{}
}

// NewTestTransport creates a new, empty, TestTransport.
func NewTestTransport() *TestTransport {
	return &TestTransport{
		runners: make(map[helium.NodeID]*Runner),
		gates:   make(map[helium.NodeID]chan struct{}),
	}
}

// AddRunner registers a runner as the endpoint for its node id.
func (t *TestTransport) AddRunner(r *Runner) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.runners[r.NodeID()] = r
}

// For returns the ShareTransport to be used by node nid.
func (t *TestTransport) For(nid helium.NodeID) ShareTransport {
	return &testNodeTransport{t: t, self: nid}
}

// GateShares holds back all shares sent by node nid until the returned function is called.
func (t *TestTransport) GateShares(nid helium.NodeID) (release func()) {
	gate := make(chan struct{})
	t.mu.Lock()
	t.gates[nid] = gate
	t.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			t.mu.Lock()
			delete(t.gates, nid)
			t.mu.Unlock()
			close(gate)
		})
	}
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

func (t *TestTransport) gate(nid helium.NodeID) chan struct{} {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.gates[nid]
}

type testNodeTransport struct {
	t    *TestTransport
	self helium.NodeID
}

func (nt *testNodeTransport) PutShare(ctx context.Context, pd Descriptor, share Share) error {
	if gate := nt.t.gate(nt.self); gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	dst, err := nt.t.runner(pd.Aggregator)
	if err != nil {
		return err
	}
	return dst.HandleShare(ctx, share)
}

func (nt *testNodeTransport) GetAggregationOutput(ctx context.Context, pd Descriptor) (Share, error) {
	src, err := nt.t.runner(pd.Aggregator)
	if err != nil {
		return Share{}, err
	}
	aggOut, err := src.GetAggregationOutput(ctx, pd)
	if err != nil {
		return Share{}, err
	}
	return aggOut.Share, nil
}
