package protocols

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/heliumtest"
	"github.com/ChristianMct/helium/objectstore"
	"github.com/ChristianMct/helium/utils"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"golang.org/x/sync/errgroup"
)

const testTimeout = 2 * time.Minute

var (
	testConf      = Config{MaxParticipation: 1}
	testCoordConf = CoordinatorConfig{MaxProtoPerNode: 1}
)

// testRunners is a helper + N session nodes setting on an in-memory transport,
// coordinated by the helper.
type testRunners struct {
	sess   *heliumtest.Sessions
	hid    helium.NodeID
	trans  *TestTransport
	coord  *CentralCoordinator
	helper *Runner
	nodes  map[helium.NodeID]*Runner
	nids   []helium.NodeID // sorted session node ids
	sigs   []Signature
	ksin   KeySwitchInputProvider
}

func newTestRunners(t *testing.T, N, T int) *testRunners {
	hid := helium.NodeID("helper")
	testSess, err := heliumtest.NewSessions(N, T, TestPN12QP109, hid)
	require.NoError(t, err)

	ct := testSess.Encryptor.EncryptZeroNew(testSess.RlweParams.MaxLevel())
	zeroKey := rlwe.NewSecretKey(testSess.RlweParams)
	te := &testRunners{
		sess:  testSess,
		hid:   hid,
		trans: NewTestTransport(),
		nodes: make(map[helium.NodeID]*Runner, N),
		ksin: func(ctx context.Context, pd Descriptor) (*KeySwitchInput, error) {
			return &KeySwitchInput{OutputKey: zeroKey, InpuCt: ct}, nil
		},
		sigs: []Signature{
			{Type: CKG},
			{Type: RTG, Args: map[string]string{"GalEl": "5"}},
			{Type: RTG, Args: map[string]string{"GalEl": "25"}},
			{Type: RKG},
			{Type: DEC, Args: map[string]string{"target": "node-0", "smudging": "40"}},
		},
	}

	te.helper = te.newRunner(t, hid, testSess.Helper)
	te.coord, err = NewCentralCoordinator(hid, testSess.Helper, testCoordConf, te.helper)
	require.NoError(t, err)
	for nid, nsess := range testSess.Nodes {
		te.nodes[nid] = te.newRunner(t, nid, nsess)
		te.nids = append(te.nids, nid)
	}
	slices.Sort(te.nids)
	return te
}

func (te *testRunners) newRunner(t *testing.T, nid helium.NodeID, sess *helium.Session) *Runner {
	e, err := NewRunner(nid, sess, testConf, te.trans.For(nid),
		NewObjectStoreResultBackend(objectstore.NewMemObjectStore(), sess.ID), te.ksin)
	require.NoError(t, err)
	te.trans.AddRunner(e)
	return e
}

// run runs e in g, driven by the test coordinator.
func (te *testRunners) run(g *errgroup.Group, ctx context.Context, e *Runner) {
	g.Go(func() error {
		if err := e.Run(ctx, te.coord); err != nil {
			return fmt.Errorf("error at node %s: %w", e.NodeID(), err)
		}
		return nil
	})
}

// checkOutputs verifies that e can produce a correct output for every signature.
func (te *testRunners) checkOutputs(t *testing.T, ctx context.Context, e *Runner, sigs ...Signature) {
	if len(sigs) == 0 {
		sigs = te.sigs
	}
	for _, sig := range sigs {
		pd, err := e.AwaitCompleted(ctx, sig)
		require.NoError(t, err, "node %s awaiting %s", e.NodeID(), sig)
		out, err := e.GetOutput(ctx, pd)
		require.NoError(t, err, "node %s output for %s", e.NodeID(), sig)
		checkOutput(out.Result, pd, *te.sess, t)
	}
}

func testContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(cancel)
	return ctx
}

// TestRunnerSetupAndDec runs the full set of protocols (setup + decryption) between a helper
// and N nodes, and checks that every node obtains correct outputs.
func TestRunnerSetupAndDec(t *testing.T) {
	for _, ts := range testSettings {
		if ts.T == 0 {
			ts.T = ts.N
		}
		t.Run(fmt.Sprintf("N=%d/T=%d", ts.N, ts.T), func(t *testing.T) {
			ctx := testContext(t)
			te := newTestRunners(t, ts.N, ts.T)

			g, gctx := errgroup.WithContext(ctx)
			te.run(g, gctx, te.helper)
			for _, nid := range te.nids {
				te.run(g, gctx, te.nodes[nid])
				te.coord.PeerConnected(nid)
			}

			for _, sig := range te.sigs {
				require.NoError(t, te.coord.RunSignature(ctx, sig))
			}
			te.coord.Close()
			require.NoError(t, g.Wait())

			te.checkOutputs(t, ctx, te.helper)
			for _, nid := range te.nids {
				te.checkOutputs(t, ctx, te.nodes[nid])
			}

			// the key view works at every node
			for _, e := range []*Runner{te.helper, te.nodes[te.nids[0]]} {
				kp := NewKeyProvider(e)
				_, err := kp.GetCollectivePublicKey(ctx)
				require.NoError(t, err)
				_, err = kp.GetGaloisKey(ctx, 5)
				require.NoError(t, err)
				_, err = kp.GetRelinearizationKey(ctx)
				require.NoError(t, err)
			}

			// the log is causally ordered: Started, Executing, Completed for each protocol
			seen := make(map[ID]EventType)
			for _, ev := range te.coord.Log() {
				pid := ev.Descriptor.ID()
				switch ev.EventType {
				case Started:
					_, has := seen[pid]
					require.False(t, has)
				case Executing:
					require.Equal(t, Started, seen[pid])
				case Completed:
					require.Equal(t, Executing, seen[pid])
				default:
					t.Fatalf("unexpected event %s", ev)
				}
				seen[pid] = ev.EventType
			}
		})
	}
}

// TestRunnerLateJoiner runs the protocols with only T nodes, then lets the remaining nodes
// catch up from the event log and fetch the results lazily from the helper.
func TestRunnerLateJoiner(t *testing.T) {
	for _, ts := range testSettings {
		if ts.T == 0 {
			ts.T = ts.N
		}
		t.Run(fmt.Sprintf("N=%d/T=%d", ts.N, ts.T), func(t *testing.T) {
			ctx := testContext(t)
			te := newTestRunners(t, ts.N, ts.T)
			early, late := te.nids[:ts.T], te.nids[ts.T:]

			g, gctx := errgroup.WithContext(ctx)
			te.run(g, gctx, te.helper)
			for _, nid := range early {
				te.run(g, gctx, te.nodes[nid])
				te.coord.PeerConnected(nid)
			}
			for _, sig := range te.sigs {
				require.NoError(t, te.coord.RunSignature(ctx, sig))
			}
			te.coord.Close()
			require.NoError(t, g.Wait())

			for _, nid := range early {
				te.checkOutputs(t, ctx, te.nodes[nid])
			}

			// late nodes catch up from the log
			for _, nid := range late {
				e := te.nodes[nid]
				past, live, err := te.coord.Register(ctx)
				require.NoError(t, err)
				_, more := <-live
				require.False(t, more, "the coordinator is closed")
				require.NoError(t, e.Init(ctx, past))
				te.checkOutputs(t, ctx, e)
			}
		})
	}
}

// TestRunnerRetry checks that a protocol is failed and retried with other participants
// when a participant disconnects before providing its share.
func TestRunnerRetry(t *testing.T) {
	ctx := testContext(t)
	te := newTestRunners(t, 3, 2)
	n0, n1, n2 := te.nodes["node-0"], te.nodes["node-1"], te.nodes["node-2"]
	sig := Signature{Type: CKG}

	release := te.trans.GateShares(n1.NodeID())
	defer release()

	_, spectator, err := te.coord.Register(ctx)
	require.NoError(t, err)
	nextEvent := func() Event {
		select {
		case ev := <-spectator:
			return ev
		case <-ctx.Done():
			t.Fatal("timeout waiting for event")
			return Event{}
		}
	}

	g, gctx := errgroup.WithContext(ctx)
	te.run(g, gctx, te.helper)
	te.run(g, gctx, n0)
	te.run(g, gctx, n1)
	te.coord.PeerConnected(n0.NodeID())
	te.coord.PeerConnected(n1.NodeID())

	require.NoError(t, te.coord.RunSignature(ctx, sig))

	pd1 := Descriptor{Signature: sig, Participants: []helium.NodeID{"node-0", "node-1"}, Aggregator: te.hid}
	require.Equal(t, Event{EventType: Started, Descriptor: pd1}, nextEvent())
	require.Equal(t, Event{EventType: Executing, Descriptor: pd1}, nextEvent())

	te.coord.PeerDisconnected(n1.NodeID())
	require.Equal(t, Event{EventType: Failed, Descriptor: pd1}, nextEvent())

	te.run(g, gctx, n2)
	te.coord.PeerConnected(n2.NodeID())

	pd2 := Descriptor{Signature: sig, Participants: []helium.NodeID{"node-0", "node-2"}, Aggregator: te.hid}
	require.Equal(t, Event{EventType: Started, Descriptor: pd2}, nextEvent())
	require.Equal(t, Event{EventType: Executing, Descriptor: pd2}, nextEvent())
	require.Equal(t, Event{EventType: Completed, Descriptor: pd2}, nextEvent())

	release()
	te.coord.Close()
	require.NoError(t, g.Wait())

	require.False(t, te.helper.IsRunning(pd1))
	require.True(t, te.helper.IsCompleted(pd2))
	for _, e := range []*Runner{te.helper, n0, n1, n2} {
		te.checkOutputs(t, ctx, e, sig)
	}
}

// recordingTransport records the shares sent through it.
type recordingTransport struct {
	mu     sync.Mutex
	shares []Share
	pds    []Descriptor
}

func (rt *recordingTransport) PutShare(_ context.Context, pd Descriptor, share Share) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.shares = append(rt.shares, share)
	rt.pds = append(rt.pds, pd)
	return nil
}

func (rt *recordingTransport) GetAggregationOutput(context.Context, Descriptor) (Share, error) {
	return Share{}, fmt.Errorf("not available")
}

func (rt *recordingTransport) sent() []Descriptor {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return slices.Clone(rt.pds)
}

// TestRunnerStateMachine drives single runners by hand, without coordinator nor
// concurrent nodes, and checks the state transitions and emitted actions.
func TestRunnerStateMachine(t *testing.T) {
	ctx := testContext(t)
	hid := helium.NodeID("helper")
	testSess, err := heliumtest.NewSessions(3, 3, TestPN12QP109, hid)
	require.NoError(t, err)
	nids := make([]helium.NodeID, 0, len(testSess.Nodes))
	for nid := range testSess.Nodes {
		nids = append(nids, nid)
	}
	slices.Sort(nids)

	pdCkg := Descriptor{Signature: Signature{Type: CKG}, Participants: nids, Aggregator: hid}
	pdRtg := Descriptor{Signature: Signature{Type: RTG, Args: map[string]string{"GalEl": "5"}}, Participants: nids, Aggregator: hid}
	started := func(pd Descriptor) Event { return Event{EventType: Started, Descriptor: pd} }
	executing := func(pd Descriptor) Event { return Event{EventType: Executing, Descriptor: pd} }
	completed := func(pd Descriptor) Event { return Event{EventType: Completed, Descriptor: pd} }
	failed := func(pd Descriptor) Event { return Event{EventType: Failed, Descriptor: pd} }

	newNode := func(nid helium.NodeID) (*Runner, *recordingTransport) {
		rt := &recordingTransport{}
		e, err := NewRunner(nid, testSess.Nodes[nid], testConf, rt,
			NewObjectStoreResultBackend(objectstore.NewMemObjectStore(), testSess.SessParams.ID), nil)
		require.NoError(t, err)
		return e, rt
	}

	t.Run("participant", func(t *testing.T) {
		e, rt := newNode(nids[0])

		// Started alone -> registered, no share yet
		require.NoError(t, e.HandleEvent(ctx, started(pdCkg)))
		require.True(t, e.IsRunning(pdCkg))
		e.genWg.Wait()
		require.Empty(t, rt.sent())

		// Executing -> one share is generated and sent
		require.NoError(t, e.HandleEvent(ctx, executing(pdCkg)))
		e.genWg.Wait()
		require.Equal(t, []Descriptor{pdCkg}, rt.sent())

		// duplicated events are ignored
		require.NoError(t, e.HandleEvent(ctx, started(pdCkg)))
		require.NoError(t, e.HandleEvent(ctx, executing(pdCkg)))
		e.genWg.Wait()
		require.Len(t, rt.sent(), 1)

		// Completed -> not running, completion is observable
		require.NoError(t, e.HandleEvent(ctx, completed(pdCkg)))
		require.False(t, e.IsRunning(pdCkg))
		require.True(t, e.IsCompleted(pdCkg))
		pd, err := e.AwaitCompleted(ctx, pdCkg.Signature)
		require.NoError(t, err)
		require.Equal(t, pdCkg, pd)

		// Failed -> not running, and a re-Started identical descriptor is processed again
		require.NoError(t, e.HandleEvent(ctx, started(pdRtg)))
		require.NoError(t, e.HandleEvent(ctx, executing(pdRtg)))
		e.genWg.Wait() // otherwise the failure may (legitimately) cancel the share generation
		require.NoError(t, e.HandleEvent(ctx, failed(pdRtg)))
		require.False(t, e.IsRunning(pdRtg))
		require.NoError(t, e.HandleEvent(ctx, started(pdRtg)))
		require.NoError(t, e.HandleEvent(ctx, executing(pdRtg)))
		require.True(t, e.IsRunning(pdRtg))
		e.genWg.Wait()
		require.Equal(t, []Descriptor{pdCkg, pdRtg, pdRtg}, rt.sent())

		// a pure participant does not know the aggregation state
		_, known := e.MissingShares(pdRtg)
		require.False(t, known)

		// no events are emitted by a pure participant
		require.Empty(t, e.outbox)
	})

	t.Run("init", func(t *testing.T) {
		e, rt := newNode(nids[1])
		log := []Event{
			started(pdCkg), executing(pdCkg), completed(pdCkg),
			started(pdRtg),
		}
		require.NoError(t, e.Init(ctx, log))
		e.genWg.Wait()
		require.Empty(t, rt.sent(), "no share before the aggregator is executing")
		require.True(t, e.IsCompleted(pdCkg))
		require.True(t, e.IsRunning(pdRtg))

		e, rt = newNode(nids[2])
		require.NoError(t, e.Init(ctx, append(log, executing(pdRtg))))
		e.genWg.Wait()
		require.Equal(t, []Descriptor{pdRtg}, rt.sent(), "only the still-executing protocol gets a share")
	})

	t.Run("aggregator", func(t *testing.T) {
		rt := &recordingTransport{}
		helper, err := NewRunner(hid, testSess.Helper, testConf, rt,
			NewObjectStoreResultBackend(objectstore.NewMemObjectStore(), testSess.SessParams.ID), nil)
		require.NoError(t, err)

		// unknown protocol
		_, known := helper.MissingShares(pdCkg)
		require.False(t, known)
		require.ErrorIs(t, helper.HandleShare(ctx, Share{ShareMetadata: ShareMetadata{ProtocolID: pdCkg.ID()}}), ErrProtocolNotRunning)

		// Started -> aggregation state is created and Executing is emitted, once
		require.NoError(t, helper.HandleEvent(ctx, started(pdCkg)))
		require.NoError(t, helper.HandleEvent(ctx, started(pdCkg)))
		require.True(t, helper.IsRunning(pdCkg))
		require.Equal(t, []Event{executing(pdCkg)}, helper.outbox)
		missing, known := helper.MissingShares(pdCkg)
		require.True(t, known)
		require.True(t, missing.Equals(utils.NewSet(nids)))

		// feeds the shares of all participants, generated by hand
		for i, nid := range nids {
			p, err := NewProtocol(pdCkg, testSess.Nodes[nid])
			require.NoError(t, err)
			in, err := p.ReadCRP()
			require.NoError(t, err)
			sk, err := testSess.Nodes[nid].GetSecretKeyForGroup(pdCkg.Participants)
			require.NoError(t, err)
			share := p.AllocateShare()
			require.NoError(t, p.GenShare(sk, in, &share))
			require.NoError(t, helper.HandleShare(ctx, share))
			missing, known := helper.MissingShares(pdCkg)
			require.True(t, known)
			require.Len(t, missing, len(nids)-i-1)
			if i < len(nids)-1 {
				require.True(t, helper.IsRunning(pdCkg))
			}
		}
		require.False(t, helper.IsRunning(pdCkg))
		require.True(t, helper.IsCompleted(pdCkg))
		require.Equal(t, []Event{executing(pdCkg), completed(pdCkg)}, helper.outbox)
		require.Empty(t, rt.sent(), "the helper is not a participant")

		out, err := helper.GetOutput(ctx, pdCkg)
		require.NoError(t, err)
		checkOutput(out.Result, pdCkg, *testSess, t)

		// a restarted helper restores the completion from its backend
		restarted, err := NewRunner(hid, testSess.Helper, testConf, rt, helper.results, nil)
		require.NoError(t, err)
		restored, err := restarted.RestoreCompleted(pdCkg.Signature, pdRtg.Signature)
		require.NoError(t, err)
		require.Equal(t, []Descriptor{pdCkg}, restored)
		out, err = restarted.GetOutput(ctx, pdCkg)
		require.NoError(t, err)
		checkOutput(out.Result, pdCkg, *testSess, t)
	})
}
