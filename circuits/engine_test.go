package circuits

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ChristianMct/helium/sessions"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
	"github.com/tuneinsight/lattigo/v5/schemes/ckks"
	"golang.org/x/sync/errgroup"
)

const testTimeout = 2 * time.Minute

var (
	bgvParamsLiteral = bgv.ParametersLiteral{
		LogN:             12,
		Q:                []uint64{0x7ffffffec001, 0x400000008001}, // 47 + 46 bits
		P:                []uint64{0xa001},                         // 15 bits
		PlaintextModulus: 65537,
	}
	// the special modulus P must be large enough for key switching at the default scale
	// (rotations), not only after a multiplication.
	ckksParamsLiteral = ckks.ParametersLiteral{
		LogN:            12,
		LogQ:            []int{47, 46},
		LogP:            []int{47},
		LogDefaultScale: 32,
	}
	testNodeMapping = map[string]sessions.NodeID{"p1": "node-0", "p2": "node-1", "p3": "node-2", "eval": "helper"}
)

type testSetting struct {
	N int // N - total parties
	T int // T - parties in the access structure
}

var testSettings = []testSetting{
	{N: 2},
	{N: 3, T: 2},
}

// nodeIndex returns i for node-i.
func nodeIndex(nid sessions.NodeID) int {
	i, err := strconv.Atoi(string(nid[len("node-"):]))
	if err != nil {
		panic(err)
	}
	return i
}

// testEngines is a helper (evaluator) + N nodes (input providers) setting on an in-process transport.
type testEngines struct {
	sess   *sessions.TestSession
	hid    sessions.NodeID
	trans  *TestEngineTransport
	coord  *LogCoordinator
	helper *Engine
	nodes  map[sessions.NodeID]*Engine
	nids   []sessions.NodeID // sorted
}

// newTestEngines creates the engines. Nodes provide the value returned by inputs for each of their input ids.
func newTestEngines(t *testing.T, N, T int, params sessions.FHEParamerersLiteralProvider, inputs func(nid sessions.NodeID, id OperandID) any) *testEngines {
	hid := sessions.NodeID("helper")
	testSess, err := sessions.NewTestSession(N, T, params, hid)
	require.NoError(t, err)

	te := &testEngines{sess: testSess, hid: hid, trans: NewTestEngineTransport(), coord: NewLogCoordinator(), nodes: make(map[sessions.NodeID]*Engine)}

	newEngine := func(nid sessions.NodeID, sess *sessions.Session, ip InputProvider) *Engine {
		e, err := NewEngine(nid, sess, Config{MaxEvaluation: 2}, te.trans.For(nid), testSess)
		require.NoError(t, err)
		require.NoError(t, e.RegisterCircuits(TestCircuits))
		e.SetInputProvider(ip)
		te.trans.AddEngine(e)
		return e
	}

	te.helper = newEngine(hid, testSess.HelperSession, NoInput)
	for nid, sess := range testSess.NodeSessions {
		nid := nid
		te.nodes[nid] = newEngine(nid, sess, func(ctx context.Context, cd Descriptor, ids []OperandID) (<-chan Input, error) {
			ch := make(chan Input, len(ids))
			for _, id := range ids {
				ch <- Input{ID: id, Value: inputs(nid, id)}
			}
			close(ch)
			return ch, nil
		})
		te.nids = append(te.nids, nid)
	}
	slices.Sort(te.nids)
	return te
}

func (te *testEngines) run(g *errgroup.Group, ctx context.Context) {
	for _, e := range append([]*Engine{te.helper}, te.enginesList()...) {
		e := e
		g.Go(func() error {
			if err := e.Run(ctx, te.coord); err != nil {
				return fmt.Errorf("engine at node %s: %w", e.NodeID(), err)
			}
			return nil
		})
	}
}

func (te *testEngines) enginesList() []*Engine {
	es := make([]*Engine, 0, len(te.nids))
	for _, nid := range te.nids {
		es = append(es, te.nodes[nid])
	}
	return es
}

func testContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(cancel)
	return ctx
}

func testDescriptor(name Name, args map[string]string, hid sessions.NodeID) Descriptor {
	return Descriptor{
		Signature:   Signature{Name: name, Args: args},
		CircuitID:   sessions.CircuitID(fmt.Sprintf("%s-0", name)),
		NodeMapping: testNodeMapping,
		Evaluator:   hid,
	}
}

func TestEngineBGV(t *testing.T) {
	for _, ts := range testSettings {
		if ts.T == 0 {
			ts.T = ts.N
		}
		t.Run(fmt.Sprintf("N=%d/T=%d", ts.N, ts.T), func(t *testing.T) {
			ctx := testContext(t)
			te := newTestEngines(t, ts.N, ts.T, bgvParamsLiteral, func(nid sessions.NodeID, _ OperandID) any {
				return []uint64{uint64(nodeIndex(nid) + 1)}
			})
			params := te.sess.FHEParameters.(bgv.Parameters)
			encoder := bgv.NewEncoder(params)
			decode := func(op *Operand) []uint64 {
				res := make([]uint64, params.MaxSlots())
				require.NoError(t, encoder.Decode(te.sess.Decryptor.DecryptNew(op.Ciphertext), res))
				return res
			}
			check := func(exp map[int]uint64, res []uint64, name Name) {
				for slot, v := range exp {
					require.Equal(t, v, res[slot], "%s at slot %d", name, slot)
				}
			}

			// inputs are encoded at slot 0 only; the rotation circuit with k=1 moves the input of p1
			// to the last slot of the first row, and the row swap moves the input of p2 to the second row
			rowLen := params.MaxSlots() / 2
			sumAll := uint64(ts.N * (ts.N + 1) / 2)
			cases := []struct {
				cd  Descriptor
				exp map[int]uint64
			}{
				{testDescriptor("bgv-add-2", nil, te.hid), map[int]uint64{0: 3}},
				{testDescriptor("bgv-mul-2", nil, te.hid), map[int]uint64{0: 2}},
				{testDescriptor("bgv-add-n", map[string]string{"n": strconv.Itoa(ts.N)}, te.hid), map[int]uint64{0: sumAll}},
				{testDescriptor("bgv-add-all", nil, te.hid), map[int]uint64{0: sumAll}},
				{testDescriptor("bgv-rot-2", map[string]string{"k": "1"}, te.hid), map[int]uint64{0: 0, rowLen - 1: 1, rowLen: 2}},
				{testDescriptor("bgv-innersum", nil, te.hid), map[int]uint64{0: 1, 1: 0}},
			}

			g, gctx := errgroup.WithContext(ctx)
			te.run(g, gctx)

			for _, c := range cases {
				require.NoError(t, te.coord.Start(ctx, c.cd))
			}
			for _, c := range cases {
				cd, err := te.helper.AwaitCompleted(ctx, c.cd.CircuitID)
				require.NoError(t, err)
				require.Equal(t, c.cd.CircuitID, cd.CircuitID)
				outID := NewOperandID(te.hid, c.cd.CircuitID, "out")

				out, err := te.helper.GetOperand(ctx, outID)
				require.NoError(t, err)
				check(c.exp, decode(out), c.cd.Name)

				// a participant fetches the output lazily from the evaluator
				fetched, err := te.nodes[te.nids[0]].GetOperand(ctx, outID)
				require.NoError(t, err)
				check(c.exp, decode(fetched), c.cd.Name)
			}

			require.NoError(t, te.helper.AwaitIdle(ctx))
			te.coord.Close()
			require.NoError(t, g.Wait())
		})
	}
}

func TestEngineCKKS(t *testing.T) {
	for _, ts := range testSettings {
		if ts.T == 0 {
			ts.T = ts.N
		}
		t.Run(fmt.Sprintf("N=%d/T=%d", ts.N, ts.T), func(t *testing.T) {
			ctx := testContext(t)
			te := newTestEngines(t, ts.N, ts.T, ckksParamsLiteral, func(nid sessions.NodeID, _ OperandID) any {
				return []float64{(float64(nodeIndex(nid)) + 1.0) / 3}
			})
			params := te.sess.FHEParameters.(ckks.Parameters)
			encoder := ckks.NewEncoder(params)
			decode := func(op *Operand) []float64 {
				res := make([]float64, params.MaxSlots())
				require.NoError(t, encoder.Decode(te.sess.Decryptor.DecryptNew(op.Ciphertext), res))
				return res
			}

			// inputs are encoded at slot 0 only; the rotation circuit with k=1 moves the input of p1
			// to the last slot, and the conjugation leaves the (real) input of p2 in place
			lastSlot := params.MaxSlots() - 1
			cases := []struct {
				cd  Descriptor
				exp map[int]float64
			}{
				{testDescriptor("ckks-add-2", nil, te.hid), map[int]float64{0: 1.0}},
				{testDescriptor("ckks-mul-2", nil, te.hid), map[int]float64{0: 2.0 / 9.0}},
				{testDescriptor("ckks-rot-2", map[string]string{"k": "1"}, te.hid), map[int]float64{0: 2.0 / 3.0, lastSlot: 1.0 / 3.0}},
			}

			g, gctx := errgroup.WithContext(ctx)
			te.run(g, gctx)

			for _, c := range cases {
				require.NoError(t, te.coord.Start(ctx, c.cd))
			}
			for _, c := range cases {
				_, err := te.helper.AwaitCompleted(ctx, c.cd.CircuitID)
				require.NoError(t, err)
				out, err := te.helper.GetOperand(ctx, NewOperandID(te.hid, c.cd.CircuitID, "out"))
				require.NoError(t, err)
				res := decode(out)
				for slot, v := range c.exp {
					require.InDelta(t, v, res[slot], 0.0001, "%s at slot %d", c.cd.Name, slot)
				}
			}

			require.NoError(t, te.helper.AwaitIdle(ctx))
			te.coord.Close()
			require.NoError(t, g.Wait())
		})
	}
}

// TestEngineLateJoiner checks that a node catching up from the log can fetch the outputs
// of completed
func TestEngineLateJoiner(t *testing.T) {
	ctx := testContext(t)
	te := newTestEngines(t, 3, 2, bgvParamsLiteral, func(nid sessions.NodeID, _ OperandID) any {
		return []uint64{uint64(nodeIndex(nid) + 1)}
	})
	cd := testDescriptor("bgv-add-2", nil, te.hid)

	g, gctx := errgroup.WithContext(ctx)
	for _, e := range []*Engine{te.helper, te.nodes["node-0"], te.nodes["node-1"]} {
		e := e
		g.Go(func() error { return e.Run(gctx, te.coord) })
	}
	require.NoError(t, te.coord.Start(ctx, cd))
	_, err := te.helper.AwaitCompleted(ctx, cd.CircuitID)
	require.NoError(t, err)
	require.NoError(t, te.helper.AwaitIdle(ctx), "the Completed event must be published before closing")
	te.coord.Close()
	require.NoError(t, g.Wait())

	late := te.nodes["node-2"]
	past, live, err := te.coord.Register(ctx)
	require.NoError(t, err)
	_, more := <-live
	require.False(t, more)
	require.NoError(t, late.Init(ctx, past))
	require.True(t, late.IsCompleted(cd.CircuitID))
	out, err := late.GetOperand(ctx, NewOperandID(te.hid, cd.CircuitID, "out"))
	require.NoError(t, err)
	params := te.sess.FHEParameters.(bgv.Parameters)
	res := make([]uint64, params.MaxSlots())
	require.NoError(t, bgv.NewEncoder(params).Decode(te.sess.Decryptor.DecryptNew(out.Ciphertext), res))
	require.Equal(t, uint64(3), res[0])
}

// recordingTransport records the operands sent through it.
type recordingTransport struct {
	mu   sync.Mutex
	sent []Operand
}

func (rt *recordingTransport) PutOperand(_ context.Context, _ Descriptor, op Operand) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.sent = append(rt.sent, op)
	return nil
}

func (rt *recordingTransport) GetOperand(context.Context, OperandID) (*Operand, error) {
	return nil, fmt.Errorf("not available")
}

func (rt *recordingTransport) sentIDs() []OperandID {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	ids := make([]OperandID, 0, len(rt.sent))
	for _, op := range rt.sent {
		ids = append(ids, op.ID)
	}
	return ids
}

// TestEngineStateMachine drives single engines by hand, without coordinator nor
// concurrent nodes, and checks the state transitions and emitted actions.
func TestEngineStateMachine(t *testing.T) {
	ctx := testContext(t)
	hid := sessions.NodeID("helper")
	testSess, err := sessions.NewTestSession(2, 2, bgvParamsLiteral, hid)
	require.NoError(t, err)
	params := testSess.FHEParameters.(bgv.Parameters)
	encoder := bgv.NewEncoder(params)

	failing := Circuit{
		Interface: func(Signature) (Interface, error) {
			return Interface{Inputs: []Port{"//p1/in"}, Outputs: []string{"out"}}, nil
		},
		Eval: func(rt Runtime) error { return fmt.Errorf("boom") },
	}

	newEngine := func(nid sessions.NodeID, sess *sessions.Session) (*Engine, *recordingTransport) {
		rt := &recordingTransport{}
		e, err := NewEngine(nid, sess, Config{}, rt, testSess)
		require.NoError(t, err)
		require.NoError(t, e.RegisterCircuits(TestCircuits))
		require.NoError(t, e.RegisterCircuit("failing", failing))
		return e, rt
	}
	encryptInput := func(id OperandID, v uint64) Operand {
		pt := bgv.NewPlaintext(params, params.MaxLevel())
		require.NoError(t, encoder.Encode([]uint64{v}, pt))
		ct, err := testSess.Encryptor.EncryptNew(pt)
		require.NoError(t, err)
		return Operand{ID: id, Ciphertext: ct}
	}
	started := func(cd Descriptor) Event {
		return Event{EventType: Started, Descriptor: cd}
	}
	executing := func(cd Descriptor) Event {
		return Event{EventType: Executing, Descriptor: cd}
	}
	completed := func(cd Descriptor) Event {
		return Event{EventType: Completed, Descriptor: cd}
	}
	failed := func(cd Descriptor) Event {
		return Event{EventType: Failed, Descriptor: cd}
	}

	cdAdd := testDescriptor("bgv-add-2", nil, hid)
	in0, in1 := NewOperandID("node-0", cdAdd.CircuitID, "in"), NewOperandID("node-1", cdAdd.CircuitID, "in")
	outID := NewOperandID(hid, cdAdd.CircuitID, "out")

	t.Run("evaluator", func(t *testing.T) {
		e, rt := newEngine(hid, testSess.HelperSession)

		require.ErrorIs(t, e.HandleOperand(ctx, encryptInput(in0, 1)), ErrCircuitNotRunning)
		require.Error(t, e.Validate(Descriptor{Signature: Signature{Name: "unknown"}, CircuitID: "x", Evaluator: hid}))

		// Started -> the evaluation starts and Executing is emitted, once
		require.NoError(t, e.HandleEvent(ctx, started(cdAdd)))
		require.NoError(t, e.HandleEvent(ctx, started(cdAdd)))
		require.True(t, e.IsRunning(cdAdd.CircuitID))
		require.Equal(t, []Event{executing(cdAdd)}, e.outbox)

		// inputs arrive
		require.Error(t, e.HandleOperand(ctx, encryptInput(NewOperandID("node-0", cdAdd.CircuitID, "other"), 1)), "unexpected operand")
		require.NoError(t, e.HandleOperand(ctx, encryptInput(in0, 1)))
		require.True(t, e.IsRunning(cdAdd.CircuitID))
		require.NoError(t, e.HandleOperand(ctx, encryptInput(in1, 2)))
		_, err := e.AwaitCompleted(ctx, cdAdd.CircuitID)
		require.NoError(t, err)
		e.wg.Wait()
		require.False(t, e.IsRunning(cdAdd.CircuitID))
		require.Equal(t, []Event{executing(cdAdd), completed(cdAdd)}, e.outbox)
		require.Empty(t, rt.sentIDs(), "the evaluator sends no input")

		out, err := e.GetOperand(ctx, outID)
		require.NoError(t, err)
		res := make([]uint64, params.MaxSlots())
		require.NoError(t, encoder.Decode(testSess.Decryptor.DecryptNew(out.Ciphertext), res))
		require.Equal(t, uint64(3), res[0])

		// a failing evaluation emits Failed
		cdFail := testDescriptor("failing", nil, hid)
		require.NoError(t, e.HandleEvent(ctx, started(cdFail)))
		e.wg.Wait()
		require.False(t, e.IsRunning(cdFail.CircuitID))
		require.False(t, e.IsCompleted(cdFail.CircuitID))
		require.Equal(t, failed(cdFail), e.outbox[len(e.outbox)-1])
	})

	t.Run("participant", func(t *testing.T) {
		e, rt := newEngine("node-0", testSess.NodeSessions["node-0"])
		e.SetInputProvider(func(ctx context.Context, cd Descriptor, ids []OperandID) (<-chan Input, error) {
			ch := make(chan Input, len(ids))
			for _, id := range ids {
				ch <- Input{ID: id, Value: []uint64{1}}
			}
			close(ch)
			return ch, nil
		})

		// Started alone -> registered, no input sent
		require.NoError(t, e.HandleEvent(ctx, started(cdAdd)))
		e.wg.Wait()
		require.True(t, e.IsRunning(cdAdd.CircuitID))
		require.Empty(t, rt.sentIDs())

		// Executing -> the input is sent, once
		require.NoError(t, e.HandleEvent(ctx, executing(cdAdd)))
		require.NoError(t, e.HandleEvent(ctx, executing(cdAdd)))
		e.wg.Wait()
		require.Equal(t, []OperandID{in0}, rt.sentIDs())

		// Completed -> not running, completion is observable
		require.NoError(t, e.HandleEvent(ctx, completed(cdAdd)))
		require.False(t, e.IsRunning(cdAdd.CircuitID))
		cd, err := e.AwaitCompleted(ctx, cdAdd.CircuitID)
		require.NoError(t, err)
		require.Equal(t, cdAdd, cd)
		require.Empty(t, e.outbox, "a participant emits no event")

		// Failed drops the circuit
		cdMul := testDescriptor("bgv-mul-2", nil, hid)
		require.NoError(t, e.HandleEvent(ctx, started(cdMul)))
		require.NoError(t, e.HandleEvent(ctx, failed(cdMul)))
		require.False(t, e.IsRunning(cdMul.CircuitID))
	})

	t.Run("init", func(t *testing.T) {
		e, rt := newEngine("node-1", testSess.NodeSessions["node-1"])
		e.SetInputProvider(func(ctx context.Context, cd Descriptor, ids []OperandID) (<-chan Input, error) {
			ch := make(chan Input, len(ids))
			for _, id := range ids {
				ch <- Input{ID: id, Value: []uint64{1}}
			}
			close(ch)
			return ch, nil
		})
		cdMul := testDescriptor("bgv-mul-2", nil, hid)
		require.NoError(t, e.Init(ctx, []Event{
			started(cdAdd), executing(cdAdd), completed(cdAdd),
			started(cdMul), executing(cdMul),
		}))
		e.wg.Wait()
		require.True(t, e.IsCompleted(cdAdd.CircuitID))
		require.True(t, e.IsRunning(cdMul.CircuitID))
		require.Equal(t, []OperandID{NewOperandID("node-1", cdMul.CircuitID, "in")}, rt.sentIDs(), "only the still-executing circuit gets an input")
	})
}
