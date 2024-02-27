package coordinator

import (
	"github.com/ldsec/helium/pkg/pkg"
)

type TestCoordinator struct {
	incoming, outgoing chan Event
	clients            map[pkg.NodeID]*TestCoordinator
	done               chan struct{}
}

func NewTestCoordinator() *TestCoordinator {
	tc := &TestCoordinator{incoming: make(chan Event), outgoing: make(chan Event), clients: make(map[pkg.NodeID]*TestCoordinator), done: make(chan struct{})}
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

func (tc *TestCoordinator) NewNodeCoordinator(nid pkg.NodeID) *TestCoordinator {
	tcc := &TestCoordinator{incoming: make(chan Event), outgoing: make(chan Event)}
	tc.clients[nid] = tcc
	return tcc
}

func (tc *TestCoordinator) Incoming() <-chan Event {
	return tc.incoming
}

func (tc *TestCoordinator) Outgoing() chan<- Event {
	return tc.outgoing
}

func (tc *TestCoordinator) New(ev Event) {
	tc.incoming <- ev
}

func (tc *TestCoordinator) Close() {
	close(tc.incoming)
}
