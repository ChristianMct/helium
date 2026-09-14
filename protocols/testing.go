package protocols

import (
	"context"
	"fmt"
	"sync"

	"github.com/ChristianMct/helium"
)

// TestEngineTransport is an in-memory ShareTransport connecting a set of MHEMPC
// engines running in the same process. Shares and queries are routed to the
// engine of the protocol's aggregator. Shares sent by a given node can be held
// back with GateShares, to simulate slow or failing participants.
type TestEngineTransport struct {
	mu      sync.Mutex
	engines map[helium.NodeID]*MHEMPC
	gates   map[helium.NodeID]chan struct{}
}

// NewTestEngineTransport creates a new, empty, TestEngineTransport.
func NewTestEngineTransport() *TestEngineTransport {
	return &TestEngineTransport{
		engines: make(map[helium.NodeID]*MHEMPC),
		gates:   make(map[helium.NodeID]chan struct{}),
	}
}

// AddEngine registers an engine as the endpoint for its node id.
func (t *TestEngineTransport) AddEngine(e *MHEMPC) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.engines[e.NodeID()] = e
}

// For returns the ShareTransport to be used by node nid.
func (t *TestEngineTransport) For(nid helium.NodeID) ShareTransport {
	return &testEngineNodeTransport{t: t, self: nid}
}

// GateShares holds back all shares sent by node nid until the returned function is called.
func (t *TestEngineTransport) GateShares(nid helium.NodeID) (release func()) {
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

func (t *TestEngineTransport) engine(nid helium.NodeID) (*MHEMPC, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, has := t.engines[nid]
	if !has {
		return nil, fmt.Errorf("no engine for node %s", nid)
	}
	return e, nil
}

func (t *TestEngineTransport) gate(nid helium.NodeID) chan struct{} {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.gates[nid]
}

type testEngineNodeTransport struct {
	t    *TestEngineTransport
	self helium.NodeID
}

func (nt *testEngineNodeTransport) PutShare(ctx context.Context, pd Descriptor, share Share) error {
	if gate := nt.t.gate(nt.self); gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	dst, err := nt.t.engine(pd.Aggregator)
	if err != nil {
		return err
	}
	return dst.HandleShare(ctx, share)
}

func (nt *testEngineNodeTransport) GetAggregationOutput(ctx context.Context, pd Descriptor) (Share, error) {
	src, err := nt.t.engine(pd.Aggregator)
	if err != nil {
		return Share{}, err
	}
	aggOut, err := src.GetAggregationOutput(ctx, pd)
	if err != nil {
		return Share{}, err
	}
	return aggOut.Share, nil
}
