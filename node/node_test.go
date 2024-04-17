package node

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ChristianMct/helium/circuit"
	"github.com/ChristianMct/helium/services/compute"
	"github.com/ChristianMct/helium/services/setup"
	"github.com/ChristianMct/helium/session"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
	"golang.org/x/net/context"
	"golang.org/x/sync/errgroup"
)

type TestCircuitSig struct {
	circuit.Signature
	ExpResult uint64
}

type testSetting struct {
	N           int // N - total parties
	T           int // T - parties in the access structure
	CircuitSigs []TestCircuitSig
	Reciever    session.NodeID
	Rep         int // numer of repetition for each circuit
}

var testSessionParameters = session.Parameters{
	ID:            "test-session",
	FHEParameters: bgv.ParametersLiteral{LogN: 12, LogQ: []int{45, 45}, LogP: []int{19}, PlaintextModulus: 79873},
	// Threshold:     set by test
}

var testSetupDescription = setup.Description{
	Cpk: true,
	Rlk: true,
	Gks: []uint64{5, 25, 125},
}

var testCircuits = []TestCircuitSig{
	{Signature: circuit.Signature{Name: "bgv-add-2-dec", Args: nil}, ExpResult: 1},
	{Signature: circuit.Signature{Name: "bgv-mul-2-dec", Args: nil}, ExpResult: 0},
}

var testSettings = []testSetting{
	{N: 2, CircuitSigs: testCircuits, Reciever: "peer-0"},
	{N: 2, CircuitSigs: testCircuits, Reciever: "helper"},
	{N: 3, T: 2, CircuitSigs: testCircuits, Reciever: "peer-0"},
	{N: 3, T: 2, CircuitSigs: testCircuits, Reciever: "helper"},
	{N: 3, T: 2, CircuitSigs: testCircuits, Reciever: "helper", Rep: 10},
}

type testNode struct {
	*Node
	compute.InputProvider
	OutputReceiver chan circuit.Output
	Outputs        map[session.CircuitID]circuit.Output
}

func NewTestNodes(lt *LocalTest) (all, clients map[session.NodeID]*testNode, cloud *testNode) {
	all = make(map[session.NodeID]*testNode, len(lt.Nodes))
	cloud = &testNode{}
	cloud.Node = lt.HelperNode
	cloud.InputProvider = compute.NoInput
	cloud.Outputs = make(map[session.CircuitID]circuit.Output)
	all[cloud.id] = cloud

	clients = make(map[session.NodeID]*testNode)
	for _, n := range lt.PeerNodes {
		cli := &testNode{}
		cli.Node = n
		cli.InputProvider = compute.NoInput
		cli.Outputs = make(map[session.CircuitID]circuit.Output)
		clients[n.id] = cli
		all[n.id] = cli
	}
	return
}

func NodeIDtoTestInput(nid string) []uint64 {
	num := strings.Trim(string(nid), "per-")
	i, err := strconv.ParseUint(num, 10, 64)
	if err != nil {
		panic(err)
	}
	return []uint64{i}
}

func TestNodeSetup(t *testing.T) {

	for _, ts := range testSettings {
		if ts.T == 0 {
			ts.T = ts.N
		}
		if ts.Rep == 0 {
			ts.Rep = 1
		}

		t.Run(fmt.Sprintf("NParty=%d/T=%d/rec=%s/rep=%d", ts.N, ts.T, ts.Reciever, ts.Rep), func(t *testing.T) {
			sessParams := testSessionParameters
			sessParams.Threshold = ts.T
			lt, err := NewLocalTest(LocalTestConfig{
				PeerNodes:     ts.N,
				SessionParams: &sessParams,
			})
			require.Nil(t, err)

			all, _, cloud := NewTestNodes(lt)

			app := App{
				SetupDescription: &testSetupDescription,
			}

			ctx := session.NewBackgroundContext(sessParams.ID)
			g, runctx := errgroup.WithContext(ctx)
			for _, node := range all {
				node := node
				g.Go(func() error {
					err := cloud.Register(node.id)
					if err != nil {
						return err
					}
					cdesc, outs, err := node.Run(runctx, app, node.InputProvider, lt.coordinator, lt.transport.TransportFor(node.id))
					if err != nil {
						return err
					}
					close(cdesc)
					_, has := <-outs
					if has {
						return fmt.Errorf("node %s should have no outputs", node.id)
					}
					return nil
				})
			}

			err = g.Wait()
			if err != nil {
				t.Fatal(err)
			}

			for _, node := range all {
				resCheckCtx, runCheckCancel := context.WithTimeout(ctx, time.Second)
				setup.CheckTestSetup(resCheckCtx, t, lt.TestSession, *app.SetupDescription, node)
				runCheckCancel()
			}
		})
	}
}

func TestNodeCompute(t *testing.T) {

	for _, ts := range testSettings {
		if ts.T == 0 {
			ts.T = ts.N
		}
		if ts.Rep == 0 {
			ts.Rep = 1
		}

		t.Run(fmt.Sprintf("NParty=%d/T=%d/rec=%s/rep=%d", ts.N, ts.T, ts.Reciever, ts.Rep), func(t *testing.T) {

			sessParams := testSessionParameters
			sessParams.Threshold = ts.T
			lt, err := NewLocalTest(LocalTestConfig{
				PeerNodes:     ts.N,
				SessionParams: &sessParams,
			})
			require.NoError(t, err)

			all, clients, cloud := NewTestNodes(lt)

			for _, cli := range clients {
				cid := cli.id
				cli.InputProvider = func(ctx context.Context, _ session.CircuitID, ol circuit.OperandLabel, _ session.Session) (any, error) {
					return NodeIDtoTestInput(string(cid)), nil
				}
			}

			app := App{
				SetupDescription: &testSetupDescription,
				Circuits:         circuit.TestCircuits,
			}

			ctx := session.NewBackgroundContext(sessParams.ID)
			g, runctx := errgroup.WithContext(ctx)
			var cdescs = make(chan chan<- circuit.Descriptor)
			for _, node := range all {
				node := node
				g.Go(func() error {
					err := cloud.Register(node.id)
					if err != nil {
						return err
					}
					cdescsn, outs, err := node.Run(runctx, app, node.InputProvider, lt.coordinator, lt.transport.TransportFor(node.id))
					if err != nil {
						return err
					}
					if node.id == cloud.id {
						cdescs <- cdescsn
					}
					for out := range outs {
						node.Outputs[out.CircuitID] = out
					}
					return nil
				})
			}

			nodemap := map[string]session.NodeID{"p1": "peer-0", "p2": "peer-1", "eval": "helper", "rec": ts.Reciever}
			cdesc := <-cdescs
			expResult := make(map[session.CircuitID]uint64)
			for _, tc := range ts.CircuitSigs {
				for i := 0; i < ts.Rep; i++ {
					cid := session.CircuitID(fmt.Sprintf("%s-%d", tc.Name, i))
					cdesc <- circuit.Descriptor{Signature: circuit.Signature{Name: tc.Name}, CircuitID: cid, NodeMapping: nodemap, Evaluator: cloud.id}
					expResult[cid] = tc.ExpResult
				}
			}
			close(cdesc)

			err = g.Wait()
			if err != nil {
				t.Fatal(err)
			}

			require.Nil(t, err)
			encoder := bgv.NewEncoder(lt.Params)

			rec := all[ts.Reciever]
			for cid, expRes := range expResult {
				out, has := rec.Outputs[cid]
				require.True(t, has, "reciever should have an output")
				delete(rec.Outputs, cid)
				pt := &rlwe.Plaintext{Element: out.Ciphertext.Element, Value: out.Ciphertext.Value[0]}
				res := make([]uint64, lt.Params.MaxSlots())
				encoder.Decode(pt, res)
				//fmt.Println(out.OperandLabel, res[:10])
				require.Equal(t, expRes, res[0])
			}

			for nid, n := range all {
				require.Empty(t, n.Outputs, "node %s should have no extra outputs", nid)
			}

		})
	}
}
