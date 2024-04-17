package coordinator

import (
	"context"
	"fmt"
	"sync"

	"github.com/ChristianMct/helium/session"
)

type EventType any

type Log[T EventType] []T

type Channel[T EventType] struct {
	Incoming <-chan T
	Outgoing chan<- T
}

type channel[T EventType] struct {
	incoming chan T
	outgoing chan T
}

func (c *channel[T]) Channel() *Channel[T] {
	return &Channel[T]{Incoming: c.incoming, Outgoing: c.outgoing}
}

type Coordinator[T EventType] interface {
	Register(ctx context.Context) (evChan *Channel[T], present int, err error)
}

type TestCoordinator[T EventType] struct {
	hid     session.NodeID
	log     Log[T]
	closed  bool
	c       channel[T]
	clients []chan T

	l sync.Mutex
}

func NewTestCoordinator[T EventType](hid session.NodeID) *TestCoordinator[T] {
	tc := &TestCoordinator[T]{hid: hid,
		log:     make([]T, 0),
		c:       channel[T]{incoming: make(chan T), outgoing: make(chan T)},
		clients: make([]chan T, 0)}
	go func() {
		for ev := range tc.c.outgoing {
			tc.l.Lock()
			tc.log = append(tc.log, ev)
			for _, cli := range tc.clients {
				cli <- ev
			}
			tc.l.Unlock()
		}
		tc.l.Lock()
		tc.closed = true
		for _, cli := range tc.clients {
			close(cli)
		}
		tc.l.Unlock()
	}()
	return tc
}

func (tc *TestCoordinator[T]) Close() {
	close(tc.c.incoming)
}

func (tc *TestCoordinator[T]) Register(ctx context.Context) (evChan *Channel[T], present int, err error) {

	tc.l.Lock()
	defer tc.l.Unlock()

	nid, has := session.NodeIDFromContext(ctx)
	if !has {
		return nil, 0, fmt.Errorf("no node id found in context")
	}

	if nid == tc.hid {
		return tc.c.Channel(), 0, nil
	}

	p := len(tc.log)
	cliC := channel[T]{incoming: make(chan T, p), outgoing: make(chan T)}
	for _, ev := range tc.log {
		cliC.incoming <- ev
	}
	if tc.closed {
		close(cliC.incoming)
	} else {
		tc.clients = append(tc.clients, cliC.incoming)
	}

	return cliC.Channel(), p, nil
}
