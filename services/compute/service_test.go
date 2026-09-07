package compute

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/ChristianMct/helium/circuits"
	"github.com/ChristianMct/helium/objectstore"
	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/sessions"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
	"github.com/tuneinsight/lattigo/v5/schemes/ckks"
	"golang.org/x/sync/errgroup"
)

var testCircuits = circuits.TestCircuits

type testSetting struct {
	N        int // N - total parties
	T        int // T - parties in the access structure
	Reciever sessions.NodeID
	Rep      int // numer of repetition for each circuit
}

var testNodeMapping = map[string]sessions.NodeID{"p1": "node-0", "p2": "node-1", "eval": "helper"}

var testSettings = []testSetting{
	{N: 2, Reciever: "node-0"},
	{N: 2, Reciever: "helper"},
	{N: 3, T: 2, Reciever: "node-0"},
	{N: 3, T: 2, Reciever: "helper"},
	{N: 3, T: 2, Reciever: "helper", Rep: 10},
}

type testnode struct {
	*Service
	InputProvider
	*sessions.Session
	engine *protocols.MHEMPC

	OutputReceiver chan circuits.Output
	Outputs        map[sessions.CircuitID]circuits.Output
}

// computeTest is a helper + N nodes compute setting, coordinated by the helper, on in-process transports.
type computeTest struct {
	testSess *sessions.TestSession
	hid      sessions.NodeID
	all      map[sessions.NodeID]*testnode
	clients  map[sessions.NodeID]*testnode
	clou     *testnode

	coord     *protocols.CentralCoordinator
	circCoord *LogCoordinator
	ctTrans   *testNodeTrans
}

func newComputeTest(t *testing.T, ts testSetting, params sessions.FHEParamerersLiteralProvider) *computeTest {
	hid := sessions.NodeID("helper")
	testSess, err := sessions.NewTestSession(ts.N, ts.T, params, hid)
	require.NoError(t, err)

	ct := &computeTest{
		testSess:  testSess,
		hid:       hid,
		all:       make(map[sessions.NodeID]*testnode, ts.N+1),
		clients:   make(map[sessions.NodeID]*testnode, ts.N),
		circCoord: NewLogCoordinator(),
	}

	conf := ServiceConfig{CircQueueSize: 300, MaxCircuitEvaluation: 5}
	engTrans := protocols.NewTestEngineTransport()

	// the engine must be created before the service (which the engine calls for its inputs),
	// and the coordinator before the helper's service (which requests protocols to it).
	newNode := func(nid sessions.NodeID, sess *sessions.Session, makeRunner func(*protocols.MHEMPC) KeyOperationRunner) *testnode {
		n := &testnode{Session: sess, OutputReceiver: make(chan circuits.Output), Outputs: make(map[sessions.CircuitID]circuits.Output)}
		var err error
		n.engine, err = protocols.NewMHEMPC(nid, sess, protocols.Config{MaxParticipation: 1}, engTrans.For(nid),
			protocols.NewObjectStoreResultBackend(objectstore.NewMemObjectStore(), sess.ID),
			func(ctx context.Context, pd protocols.Descriptor) (*protocols.KeySwitchInput, error) {
				return n.Service.GetKeySwitchInput(ctx, pd)
			})
		require.NoError(t, err)
		engTrans.AddEngine(n.engine)
		n.Service, err = NewComputeService(nid, sess, conf, n.engine, makeRunner(n.engine), testSess)
		require.NoError(t, err)
		require.NoError(t, n.RegisterCircuits(testCircuits))
		n.InputProvider = NoInput
		ct.all[nid] = n
		return n
	}

	ct.clou = newNode(hid, testSess.HelperSession, func(e *protocols.MHEMPC) KeyOperationRunner {
		var err error
		ct.coord, err = protocols.NewCentralCoordinator(hid, testSess.HelperSession, protocols.CoordinatorConfig{MaxProtoPerNode: 1}, e)
		require.NoError(t, err)
		return ct.coord
	})
	ct.ctTrans = newTestTransport(ct.clou.Service)

	for _, nid := range testSess.SessParams.Nodes {
		ct.clients[nid] = newNode(nid, testSess.NodeSessions[nid], func(*protocols.MHEMPC) KeyOperationRunner { return nil })
		ct.coord.PeerConnected(nid)
	}
	return ct
}

// run runs all nodes in g. The helper evaluates the circuits from cdescs and closes the
// coordination once its service returns.
func (ct *computeTest) run(ctx context.Context, g *errgroup.Group, cdescs <-chan circuits.Descriptor) {
	for nid, n := range ct.all {
		nid, n := nid, n
		g.Go(func() error {
			for out := range n.OutputReceiver {
				n.Outputs[out.CircuitID] = out
			}
			return nil
		})
		g.Go(func() error {
			return errors.WithMessagef(n.engine.Run(ctx, ct.coord), "engine at node %s", nid)
		})
		g.Go(func() error {
			var err error
			if nid == ct.hid {
				err = n.Service.Run(ctx, n.InputProvider, n.OutputReceiver, ct.circCoord, ct.ctTrans, cdescs)
				ct.circCoord.Close()
				ct.coord.Close()
			} else {
				err = n.Service.Run(ctx, n.InputProvider, n.OutputReceiver, ct.circCoord, ct.ctTrans, nil)
			}
			return errors.WithMessagef(err, "service at node %s", nid)
		})
	}
}

func testCircuitDescriptors(ts testSetting, sigs []circuits.Signature) (cds []circuits.Descriptor) {
	for _, tsig := range sigs {
		for r := 0; r < ts.Rep; r++ {
			cid := sessions.CircuitID(fmt.Sprintf("%s-%d", tsig.Name, r))
			nm := make(map[string]sessions.NodeID, len(testNodeMapping)+1)
			for k, v := range testNodeMapping {
				nm[k] = v
			}
			nm["rec"] = ts.Reciever
			cds = append(cds, circuits.Descriptor{Signature: tsig, CircuitID: cid, NodeMapping: nm, Evaluator: "helper"})
		}
	}
	return cds
}

func TestCloudAssistedComputeBGV(t *testing.T) {

	bgvParamsLiteral := bgv.ParametersLiteral{
		LogN:             12,
		Q:                []uint64{0x7ffffffec001, 0x400000008001}, // 47 + 46 bits
		P:                []uint64{0xa001},                         // 15 bits
		PlaintextModulus: 65537,
	}

	var testCircuitSigs = []circuits.Signature{
		{Name: "bgv-add-2-dec", Args: nil},
		{Name: "bgv-mul-2-dec", Args: nil},
		{Name: "bgv-add-all-dec", Args: nil},
	}

	// TODO: improve test-to-result mapping
	expRes := func(tc testSetting, sig circuits.Signature) uint64 {
		switch sig.Name {
		case "bgv-add-2-dec":
			return 3
		case "bgv-add-all-dec":
			if tc.N == 2 {
				return 3
			}
			return 6
		case "bgv-mul-2-dec":
			return 2
		default:
			panic("unknown signature")
		}
	}

	nodeIDtoTestInput := func(nid string) []uint64 {
		num := strings.Trim(string(nid), "node-")
		i, err := strconv.ParseUint(num, 10, 64)
		if err != nil {
			panic(err)
		}
		return []uint64{i + 1}
	}

	for _, ts := range testSettings {
		if ts.T == 0 {
			ts.T = ts.N
		}

		if ts.Rep == 0 {
			ts.Rep = 1
		}

		t.Run(fmt.Sprintf("NParty=%d/T=%d/rec=%s/rep=%d", ts.N, ts.T, ts.Reciever, ts.Rep), func(t *testing.T) {

			ct := newComputeTest(t, ts, bgvParamsLiteral)
			for nid, cli := range ct.clients {
				nid := nid
				cli.InputProvider = func(ctx context.Context, sess sessions.Session, cd circuits.Descriptor) (chan circuits.Input, error) {
					var opl circuits.OperandLabel
					switch cd.Signature.Name {
					case "bgv-add-all-dec":
						opl = circuits.OperandLabel(fmt.Sprintf("//%s/%s/sum", nid, cd.CircuitID))
					case "bgv-add-2-dec", "bgv-mul-2-dec":
						opl = circuits.OperandLabel(fmt.Sprintf("//%s/%s/in", nid, cd.CircuitID))
					default:
						return nil, fmt.Errorf("unknown signature %s", cd.Signature.Name)
					}
					in := make(chan circuits.Input, 1)
					in <- circuits.Input{OperandLabel: opl, OperandValue: nodeIDtoTestInput(string(nid))}
					close(in)
					return in, nil
				}
			}

			ctx := sessions.NewBackgroundContext(ct.testSess.SessParams.ID)
			g, ctx := errgroup.WithContext(ctx)
			cdescs := make(chan circuits.Descriptor)
			ct.run(ctx, g, cdescs)

			expResult := make(map[sessions.CircuitID]uint64)
			for _, cd := range testCircuitDescriptors(ts, testCircuitSigs) {
				cdescs <- cd
				expResult[cd.CircuitID] = expRes(ts, cd.Signature)
			}
			close(cdescs)

			require.NoError(t, g.Wait()) // waits for all parties to terminate

			bgvParams, err := bgv.NewParameters(ct.testSess.RlweParams, bgvParamsLiteral.PlaintextModulus)
			require.Nil(t, err)
			encoder := bgv.NewEncoder(bgvParams)

			rec := ct.all[ts.Reciever]
			for cid, expRes := range expResult {
				out, has := rec.Outputs[cid]
				require.True(t, has, "reciever should have an output")
				delete(rec.Outputs, cid)
				pt := &rlwe.Plaintext{Element: out.Ciphertext.Element, Value: out.Ciphertext.Value[0]}
				pt.IsNTT = out.Ciphertext.IsNTT
				res := make([]uint64, bgvParams.MaxSlots())
				err := encoder.Decode(pt, res)
				require.Nil(t, err)
				require.Equal(t, expRes, res[0])
			}

			for nid, n := range ct.all {
				require.Empty(t, n.Outputs, "node %s should have no extra outputs", nid)
			}
		})
	}
}

func TestCloudAssistedComputeCKKS(t *testing.T) {

	ckksParamsLiteral := ckks.ParametersLiteral{
		LogN:            12,
		Q:               []uint64{0x7ffffffec001, 0x400000008001}, // 47 + 46 bits
		P:               []uint64{0xa001},                         // 15 bits
		LogDefaultScale: 32,
	}

	var testCircuitSigs = []circuits.Signature{
		{Name: "ckks-add-2-dec", Args: nil},
		{Name: "ckks-mul-2-dec", Args: nil},
	}

	// TODO: improve test-to-result mapping
	expRes := func(tc testSetting, sig circuits.Signature) float64 {
		switch sig.Name {
		case "ckks-add-2-dec":
			return 1.0
		case "ckks-mul-2-dec":
			return 0.2222222222222222
		default:
			panic("unknown signature")
		}
	}

	nodeIDtoTestInput := func(nid string) []float64 {
		num := strings.Trim(string(nid), "node-")
		i, err := strconv.ParseUint(num, 10, 64)
		if err != nil {
			panic(err)
		}
		return []float64{(float64(i) + 1.0) / 3}
	}

	for _, ts := range testSettings {
		if ts.T == 0 {
			ts.T = ts.N
		}

		if ts.Rep == 0 {
			ts.Rep = 1
		}

		t.Run(fmt.Sprintf("NParty=%d/T=%d/rec=%s/rep=%d", ts.N, ts.T, ts.Reciever, ts.Rep), func(t *testing.T) {

			ct := newComputeTest(t, ts, ckksParamsLiteral)
			for nid, cli := range ct.clients {
				nid := nid
				cli.InputProvider = func(ctx context.Context, sess sessions.Session, cd circuits.Descriptor) (chan circuits.Input, error) {
					in := make(chan circuits.Input, 1)
					in <- circuits.Input{OperandLabel: circuits.OperandLabel(fmt.Sprintf("//%s/%s/in", nid, cd.CircuitID)), OperandValue: nodeIDtoTestInput(string(nid))}
					close(in)
					return in, nil
				}
			}

			ctx := sessions.NewBackgroundContext(ct.testSess.SessParams.ID)
			g, ctx := errgroup.WithContext(ctx)
			cdescs := make(chan circuits.Descriptor)
			ct.run(ctx, g, cdescs)

			expResult := make(map[sessions.CircuitID]float64)
			for _, cd := range testCircuitDescriptors(ts, testCircuitSigs) {
				cdescs <- cd
				expResult[cd.CircuitID] = expRes(ts, cd.Signature)
			}
			close(cdescs)

			require.NoError(t, g.Wait()) // waits for all parties to terminate

			ckksParams, err := ckks.NewParametersFromLiteral(ckksParamsLiteral)
			require.Nil(t, err)
			encoder := ckks.NewEncoder(ckksParams)

			rec := ct.all[ts.Reciever]
			for cid, expRes := range expResult {
				out, has := rec.Outputs[cid]
				require.True(t, has, "reciever should have an output")
				delete(rec.Outputs, cid)
				pt := &rlwe.Plaintext{Element: out.Ciphertext.Element, Value: out.Ciphertext.Value[0]}
				pt.IsNTT = out.IsNTT
				pt.Scale = out.Scale

				res := make([]float64, ckksParams.MaxSlots())
				err := encoder.Decode(pt, res)
				require.Nil(t, err)
				require.InDelta(t, expRes, res[0], 0.0001) // TODO better bounds
			}

			for nid, n := range ct.all {
				require.Empty(t, n.Outputs, "node %s should have no extra outputs", nid)
			}
		})
	}
}
