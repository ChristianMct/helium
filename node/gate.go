package node

import (
	"context"
	"sync"
)

// gatePolicy describes how a gate treats the events of a coordination stream.
type gatePolicy[E any] struct {
	// key returns the key identifying the descriptor of an event (all the events of a
	// descriptor share the key).
	key func(E) string
	// gated returns whether the events of the descriptor need to be claimed by the
	// application before reaching the engine (i.e., the node has a role in it).
	gated func(E) bool
	// terminal returns whether the event terminates the descriptor (completed/failed).
	terminal func(E) bool
	// skippable returns whether the event can be skipped when a terminal event of the
	// descriptor is already held (e.g., an "executing" event).
	skippable func(E) bool
	// logf is used for diagnostics.
	logf func(string, ...any)
}

// gate is the rendez-vous point between the application (App.Main) and an engine: it
// sits between a coordination stream and the engine consuming it, and holds the events
// of the descriptors in which the node has a role until the application claims them
// (by calling the corresponding Runtime method). The events of other descriptors pass
// through. Held events are released in order, and the events of a claimed descriptor
// are forwarded in order with respect to its released events.
//
// The gate closes its downstream channel once the upstream stream is closed and the
// application has finished (see finish), so that a node catching up from a closed
// stream can still claim past events.
type gate[E any] struct {
	pol gatePolicy[E]

	out      chan E
	claims   chan claimRequest
	finished chan struct{}
	finOnce  sync.Once

	// state owned by the loop goroutine
	held    map[string][]E
	claimed map[string]bool
	seen    map[string]bool
}

type claimRequest struct {
	key   string
	known chan bool
}

func newGate[E any](pol gatePolicy[E]) *gate[E] {
	return &gate[E]{
		pol:      pol,
		out:      make(chan E),
		claims:   make(chan claimRequest),
		finished: make(chan struct{}),
		held:     make(map[string][]E),
		claimed:  make(map[string]bool),
		seen:     make(map[string]bool),
	}
}

// open filters the past events of the stream and starts forwarding its live events. It
// returns the past events to pass downstream and the downstream live channel.
func (g *gate[E]) open(ctx context.Context, past []E, live <-chan E) (fpast []E, out <-chan E) {
	for _, ev := range past {
		if g.hold(ev) {
			continue
		}
		fpast = append(fpast, ev)
	}
	go g.loop(ctx, live)
	return fpast, g.out
}

// hold records the event and returns whether it must be held.
func (g *gate[E]) hold(ev E) bool {
	k := g.pol.key(ev)
	g.seen[k] = true
	if g.pol.gated(ev) && !g.claimed[k] {
		g.held[k] = append(g.held[k], ev)
		return true
	}
	return false
}

func (g *gate[E]) loop(ctx context.Context, live <-chan E) {
	defer close(g.out)
	upstreamOpen, finished := true, false
	fin := g.finished
	for upstreamOpen || !finished {
		select {
		case ev, more := <-live:
			if !more {
				upstreamOpen = false
				live = nil
				continue
			}
			if g.hold(ev) {
				continue
			}
			if !g.forward(ctx, ev) {
				return
			}
		case req := <-g.claims:
			known := g.seen[req.key]
			g.claimed[req.key] = true
			evs := g.held[req.key]
			delete(g.held, req.key)
			req.known <- known
			if !g.release(ctx, evs) {
				return
			}
		case <-fin:
			finished = true
			fin = nil
		case <-ctx.Done():
			return
		}
	}
	if len(g.held) > 0 {
		keys := make([]string, 0, len(g.held))
		for k := range g.held {
			keys = append(keys, k)
		}
		g.pol.logf("gate closed with %d unclaimed descriptor(s): %v", len(keys), keys)
	}
}

// release forwards the held events of a descriptor, skipping the skippable ones when a
// terminal event is held.
func (g *gate[E]) release(ctx context.Context, evs []E) bool {
	hasTerminal := false
	for _, ev := range evs {
		hasTerminal = hasTerminal || g.pol.terminal(ev)
	}
	for _, ev := range evs {
		if hasTerminal && g.pol.skippable(ev) {
			continue
		}
		if !g.forward(ctx, ev) {
			return false
		}
	}
	return true
}

func (g *gate[E]) forward(ctx context.Context, ev E) bool {
	select {
	case g.out <- ev:
		return true
	case <-ctx.Done():
		return false
	}
}

// claim lets the events of the descriptor with the given key through. It returns whether
// events of this descriptor have already been seen by the gate.
func (g *gate[E]) claim(ctx context.Context, key string) (known bool, err error) {
	req := claimRequest{key: key, known: make(chan bool, 1)}
	select {
	case g.claims <- req:
	case <-ctx.Done():
		return false, ctx.Err()
	}
	select {
	case known = <-req.known:
		return known, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

// finish signals that the application is done: the gate closes its downstream channel
// once the upstream stream is also closed.
func (g *gate[E]) finish() {
	g.finOnce.Do(func() { close(g.finished) })
}

// gatedCoordinator wraps a coordinator's stream with a gate. Instantiated with
// protocols.Event and circuits.Event, it implements protocols.Coordinator and
// circuits.Coordinator respectively.
type gatedCoordinator[E any] struct {
	register func(ctx context.Context) (past []E, live <-chan E, err error)
	publish  func(ctx context.Context, ev E) error
	g        *gate[E]
}

func (gc *gatedCoordinator[E]) Register(ctx context.Context) (past []E, live <-chan E, err error) {
	past, live, err = gc.register(ctx)
	if err != nil {
		return nil, nil, err
	}
	past, live = gc.g.open(ctx, past, live)
	return past, live, nil
}

func (gc *gatedCoordinator[E]) Publish(ctx context.Context, ev E) error {
	return gc.publish(ctx, ev)
}
