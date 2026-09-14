package node

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// testEvent is a minimal event type for testing the gate.
type testEvent struct {
	key   string
	kind  string // "started", "executing", "completed"
	gated bool
}

func testGatePolicy() gatePolicy[testEvent] {
	return gatePolicy[testEvent]{
		key:       func(ev testEvent) string { return ev.key },
		gated:     func(ev testEvent) bool { return ev.gated },
		terminal:  func(ev testEvent) bool { return ev.kind == "completed" },
		skippable: func(ev testEvent) bool { return ev.kind == "executing" },
		logf:      func(string, ...any) {},
	}
}

func recv(t *testing.T, out <-chan testEvent) testEvent {
	t.Helper()
	select {
	case ev, more := <-out:
		require.True(t, more, "channel closed")
		return ev
	case <-time.After(time.Second):
		t.Fatal("no event received")
	}
	return testEvent{}
}

func expectNone(t *testing.T, out <-chan testEvent) {
	t.Helper()
	select {
	case ev := <-out:
		t.Fatalf("unexpected event %+v", ev)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestGate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("PassThroughAndHold", func(t *testing.T) {
		g := newGate(testGatePolicy())
		live := make(chan testEvent)
		past := []testEvent{{"a", "started", true}, {"x", "started", false}}
		fpast, out := g.open(ctx, past, live)
		require.Equal(t, []testEvent{{"x", "started", false}}, fpast, "gated past events are held")

		live <- testEvent{"a", "executing", true}
		live <- testEvent{"y", "started", false}
		require.Equal(t, testEvent{"y", "started", false}, recv(t, out), "non-gated events pass through")
		expectNone(t, out)

		// the claim releases the held events in order, then lets the live events through
		known, err := g.claim(ctx, "a")
		require.NoError(t, err)
		require.True(t, known)
		require.Equal(t, testEvent{"a", "started", true}, recv(t, out))
		require.Equal(t, testEvent{"a", "executing", true}, recv(t, out))
		live <- testEvent{"a", "completed", true}
		require.Equal(t, testEvent{"a", "completed", true}, recv(t, out))

		// a claim before any event is unknown, and lets subsequent events through directly
		known, err = g.claim(ctx, "b")
		require.NoError(t, err)
		require.False(t, known)
		live <- testEvent{"b", "started", true}
		require.Equal(t, testEvent{"b", "started", true}, recv(t, out))

		close(live)
		expectNone(t, out) // the app is not finished: the downstream channel stays open
		g.finish()
		_, more := <-out
		require.False(t, more)
	})

	t.Run("SkipsExecutingOfTerminatedDescriptor", func(t *testing.T) {
		g := newGate(testGatePolicy())
		live := make(chan testEvent)
		past := []testEvent{{"a", "started", true}, {"a", "executing", true}, {"a", "completed", true}}
		fpast, out := g.open(ctx, past, live)
		require.Empty(t, fpast)
		close(live) // catching up from a closed stream

		known, err := g.claim(ctx, "a")
		require.NoError(t, err)
		require.True(t, known)
		require.Equal(t, testEvent{"a", "started", true}, recv(t, out))
		require.Equal(t, testEvent{"a", "completed", true}, recv(t, out))
		g.finish()
		_, more := <-out
		require.False(t, more)
	})

	t.Run("ClaimCancelled", func(t *testing.T) {
		g := newGate(testGatePolicy())
		cctx, ccancel := context.WithCancel(ctx)
		ccancel()
		_, err := g.claim(cctx, "a") // the gate is not open: the claim blocks until cancelled
		require.ErrorIs(t, err, context.Canceled)
	})
}
