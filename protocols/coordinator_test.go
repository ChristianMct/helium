package protocols

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/heliumtest"
	"github.com/ChristianMct/helium/utils"
	"github.com/stretchr/testify/require"
)

// fakeStatus is an AggregationStatus for testing the coordinator without an engine.
type fakeStatus struct {
	mu      sync.Mutex
	missing map[ID]utils.Set[helium.NodeID] // known protocols and their missing shares
}

func (fs *fakeStatus) set(pd Descriptor, missing ...helium.NodeID) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.missing == nil {
		fs.missing = make(map[ID]utils.Set[helium.NodeID])
	}
	fs.missing[pd.ID()] = utils.NewSet(missing)
}

func (fs *fakeStatus) MissingShares(pd Descriptor) (utils.Set[helium.NodeID], bool) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	m, has := fs.missing[pd.ID()]
	return m, has
}

// eventReader reads events from a live channel with a timeout.
type eventReader struct {
	t    *testing.T
	live <-chan Event
}

func (r eventReader) next() Event {
	r.t.Helper()
	select {
	case ev, more := <-r.live:
		require.True(r.t, more, "live channel closed")
		return ev
	case <-time.After(5 * time.Second):
		r.t.Fatal("timeout waiting for event")
		return Event{}
	}
}

func (r eventReader) none() {
	r.t.Helper()
	select {
	case ev := <-r.live:
		r.t.Fatalf("unexpected event %s", ev)
	case <-time.After(50 * time.Millisecond):
	}
}

func (r eventReader) closed() {
	r.t.Helper()
	select {
	case ev, more := <-r.live:
		require.False(r.t, more, "unexpected event %s", ev)
	case <-time.After(5 * time.Second):
		r.t.Fatal("timeout waiting for the live channel to close")
	}
}

func TestCentralCoordinator(t *testing.T) {
	hid := helium.NodeID("helper")
	ev := func(et EventType, pd Descriptor) Event { return Event{EventType: et, Descriptor: pd} }

	t.Run("threshold", func(t *testing.T) {
		ctx := testContext(t)
		testSess, err := heliumtest.NewSessions(3, 2, TestPN12QP109, hid)
		require.NoError(t, err)
		fs := &fakeStatus{}
		c, err := NewCentralCoordinator(hid, testSess.Helper, CoordinatorConfig{MaxProtoPerNode: 1}, fs)
		require.NoError(t, err)

		past, live, err := c.Register(ctx)
		require.NoError(t, err)
		require.Empty(t, past)
		r := eventReader{t, live}

		// invalid signatures are rejected
		require.Error(t, c.RunSignature(ctx, Signature{Type: RTG}), "missing GalEl")
		require.Error(t, c.RunSignature(ctx, Signature{Type: DEC}), "missing target")

		// a request waits for enough participants
		ckg := Signature{Type: CKG}
		require.NoError(t, c.RunSignature(ctx, ckg))
		r.none()
		c.PeerConnected("node-0")
		r.none()
		c.PeerConnected("node-1")
		pd1 := Descriptor{Signature: ckg, Participants: []helium.NodeID{"node-0", "node-1"}, Aggregator: hid}
		require.Equal(t, ev(Started, pd1), r.next())

		// engine events are appended to the log
		require.NoError(t, c.Publish(ctx, ev(Executing, pd1)))
		require.Equal(t, ev(Executing, pd1), r.next())
		require.Error(t, c.Publish(ctx, ev(Started, pd1)), "engines cannot publish Started")

		// disconnection of a participant that provided its share is harmless
		fs.set(pd1, "node-1")
		c.PeerDisconnected("node-0")
		r.none()
		c.PeerConnected("node-0")

		// disconnection of a participant with a missing share fails and requeues the protocol
		c.PeerDisconnected("node-1")
		require.Equal(t, ev(Failed, pd1), r.next())
		require.NoError(t, c.Publish(ctx, ev(Completed, pd1)), "late completion of a failed protocol is ignored")
		r.none()

		// the retry starts as soon as a replacement connects
		c.PeerConnected("node-2")
		pd2 := Descriptor{Signature: ckg, Participants: []helium.NodeID{"node-0", "node-2"}, Aggregator: hid}
		require.Equal(t, ev(Started, pd2), r.next())
		require.NoError(t, c.Publish(ctx, ev(Completed, pd2)))
		require.Equal(t, ev(Completed, pd2), r.next())

		// MaxProtoPerNode limits the concurrent participation
		rtg5 := Signature{Type: RTG, Args: map[string]string{"GalEl": "5"}}
		rtg25 := Signature{Type: RTG, Args: map[string]string{"GalEl": "25"}}
		require.NoError(t, c.RunSignature(ctx, rtg5))
		pdRtg5 := Descriptor{Signature: rtg5, Participants: []helium.NodeID{"node-0", "node-2"}, Aggregator: hid}
		require.Equal(t, ev(Started, pdRtg5), r.next())
		require.NoError(t, c.RunSignature(ctx, rtg25))
		r.none()
		require.NoError(t, c.Publish(ctx, ev(Completed, pdRtg5)))
		require.Equal(t, ev(Completed, pdRtg5), r.next())
		pdRtg25 := Descriptor{Signature: rtg25, Participants: []helium.NodeID{"node-0", "node-2"}, Aggregator: hid}
		require.Equal(t, ev(Started, pdRtg25), r.next())
		require.NoError(t, c.Publish(ctx, ev(Completed, pdRtg25)))
		require.Equal(t, ev(Completed, pdRtg25), r.next())

		// RKG runs its first round first, then its second round with the same participants
		rkg := Signature{Type: RKG}
		require.NoError(t, c.RunSignature(ctx, rkg))
		pdRkg1 := Descriptor{Signature: Signature{Type: RKG1}, Participants: []helium.NodeID{"node-0", "node-2"}, Aggregator: hid}
		require.Equal(t, ev(Started, pdRkg1), r.next())
		require.NoError(t, c.Publish(ctx, ev(Completed, pdRkg1)))
		require.Equal(t, ev(Completed, pdRkg1), r.next())
		pdRkg := Descriptor{Signature: rkg, Participants: []helium.NodeID{"node-0", "node-2"}, Aggregator: hid}
		require.Equal(t, ev(Started, pdRkg), r.next())

		// Close waits for the running protocols
		c.Close()
		r.none()
		require.NoError(t, c.Publish(ctx, ev(Completed, pdRkg)))
		require.Equal(t, ev(Completed, pdRkg), r.next())
		r.closed()

		// a late subscriber gets the whole log and a closed channel
		past, live, err = c.Register(ctx)
		require.NoError(t, err)
		require.Equal(t, c.Log(), past)
		require.Len(t, past, 13)
		eventReader{t, live}.closed()

		require.ErrorIs(t, c.Publish(ctx, ev(Completed, pdRkg)), ErrCoordinatorClosed)
		require.ErrorIs(t, c.RunSignature(ctx, ckg), ErrCoordinatorClosed)
	})

	t.Run("full-threshold", func(t *testing.T) {
		ctx := testContext(t)
		testSess, err := heliumtest.NewSessions(3, 3, TestPN12QP109, hid)
		require.NoError(t, err)
		c, err := NewCentralCoordinator(hid, testSess.Helper, CoordinatorConfig{}, nil)
		require.NoError(t, err)
		_, live, err := c.Register(ctx)
		require.NoError(t, err)
		r := eventReader{t, live}

		// all session nodes are selected, connected or not
		ckg := Signature{Type: CKG}
		require.NoError(t, c.RunSignature(ctx, ckg))
		pd := Descriptor{Signature: ckg, Participants: testSess.SessParams.Nodes, Aggregator: hid}
		require.Equal(t, ev(Started, pd), r.next())

		// disconnections cannot fail a full-threshold protocol
		c.PeerConnected("node-0")
		c.PeerDisconnected("node-0")
		r.none()

		// explicit descriptors
		require.Error(t, c.RunDescriptor(ctx, pd), "already running")
		require.NoError(t, c.Publish(ctx, ev(Completed, pd)))
		require.Equal(t, ev(Completed, pd), r.next())
		require.Error(t, c.RunDescriptor(ctx, pd), "already completed")
		require.NoError(t, c.RunSignature(ctx, ckg), "the identical completed protocol satisfies the request")
		r.none()

		// restored protocols appear in the log
		pdRtg := Descriptor{Signature: Signature{Type: RTG, Args: map[string]string{"GalEl": "5"}}, Participants: testSess.SessParams.Nodes, Aggregator: hid}
		c.Restore(pdRtg)
		require.Equal(t, ev(Started, pdRtg), r.next())
		require.Equal(t, ev(Executing, pdRtg), r.next())
		require.Equal(t, ev(Completed, pdRtg), r.next())

		// a cancelled subscriber is released
		subCtx, cancel := context.WithCancel(ctx)
		_, live2, err := c.Register(subCtx)
		require.NoError(t, err)
		cancel()
		eventReader{t, live2}.closed()

		c.Close()
		r.closed()
	})
}
