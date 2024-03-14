package coordinator

import (
	"github.com/ldsec/helium"
)

// Coordinator defines the interface for a coordinator.
// A coordinator is a source of incoming events for the
// coordinated (downstream) component and a sink for outgoing
// events from the coordinated component.
type Coordinator interface {
	Incoming() <-chan Event
	Outgoing() chan<- Event
}

// TestCoordinator is a test implementation of a centralized coordinator
// that broadcasts its events to all its clients.
type TestCoordinator struct {
	incoming, outgoing chan Event
	clients            map[helium.NodeID]*TestCoordinator
	done               chan struct{}
}

// NewTestCoordinator creates a new test coordinator.
func NewTestCoordinator() *TestCoordinator {
	tc := &TestCoordinator{incoming: make(chan Event), outgoing: make(chan Event), clients: make(map[helium.NodeID]*TestCoordinator), done: make(chan struct{})}
	go func() {
		for ev := range tc.outgoing {
			for _, cli := range tc.clients {
				cli.incoming <- ev
			}
		}
		//log.Printf("test | closing client upstreams")
		for _, cli := range tc.clients {
			close(cli.incoming)
		}
	}()
	return tc
}

// NewPeerCoordinator creates a new node coordinator.
func (tc *TestCoordinator) NewPeerCoordinator(nid helium.NodeID) *TestCoordinator {
	tcc := &TestCoordinator{incoming: make(chan Event), outgoing: make(chan Event)}
	tc.clients[nid] = tcc
	return tcc
}

// Incoming returns the incoming event channel.
func (tc *TestCoordinator) Incoming() <-chan Event {
	return tc.incoming
}

// Outgoing returns the outgoing event channel.
func (tc *TestCoordinator) Outgoing() chan<- Event {
	return tc.outgoing
}

// LogEvent appends a new event to the coordination log.
func (tc *TestCoordinator) LogEvent(ev Event) {
	tc.incoming <- ev
}

// Close closes the coordination log.
func (tc *TestCoordinator) Close() {
	close(tc.incoming)
}
