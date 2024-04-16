package node

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/circuit"
	"github.com/ChristianMct/helium/services/compute"
	"github.com/ChristianMct/helium/services/setup"
	"github.com/ChristianMct/helium/session"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/heint"
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
	Reciever    helium.NodeID
	Rep         int // numer of repetition for each circuit
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
	Outputs        map[helium.CircuitID]circuit.Output
}

func NewTestNodes(lt *LocalTest) (all, clients map[helium.NodeID]*testNode, cloud *testNode) {
	all = make(map[helium.NodeID]*testNode, len(lt.Nodes))
	cloud = &testNode{}
	cloud.Node = lt.HelperNode
	cloud.InputProvider = compute.NoInput
	cloud.Outputs = make(map[helium.CircuitID]circuit.Output)
	all[cloud.id] = cloud

	clients = make(map[helium.NodeID]*testNode)
	for _, n := range lt.PeerNodes {
		cli := &testNode{}
		cli.Node = n
		cli.InputProvider = compute.NoInput
		cli.Outputs = make(map[helium.CircuitID]circuit.Output)
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

			//params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{T: 79873, LogN: 13, LogQ: []int{54, 54, 54}, LogP: []int{55}}) // vecmul

			params, err := heint.NewParametersFromLiteral(heint.ParametersLiteral{LogN: 12, LogQ: []int{45, 45}, LogP: []int{19}, PlaintextModulus: 79873}) // matmul
			require.Nil(t, err)
			sessParams := session.Parameters{
				ID:            "test-session",
				FHEParameters: params.ParametersLiteral(),
				Threshold:     ts.T,
			}

			lt, err := NewLocalTest(LocalTestConfig{
				PeerNodes:     ts.N,
				SessionParams: &sessParams,
			})
			require.Nil(t, err)

			testSess := lt.TestSession

			all, clients, cloud := NewTestNodes(lt)
			_, _ = clients, cloud

			ctx := helium.NewBackgroundContext(sessParams.ID)

			app := App{
				SetupDescription: &testSetupDescription,
			}

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
				log.Println("checking setup for", node.id)
				resCheckCtx, runCheckCancel := context.WithTimeout(ctx, time.Second)
				setup.CheckTestSetup(resCheckCtx, t, node.id, testSess, *app.SetupDescription, node)
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

			paramLiteral := bgv.ParametersLiteral{PlaintextModulus: 79873, LogN: 12, LogQ: []int{45, 45}, LogP: []int{19}}

			//params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{T: 79873, LogN: 13, LogQ: []int{54, 54, 54}, LogP: []int{55}}) // vecmul
			sessParams := session.Parameters{
				ID:            "test-session",
				FHEParameters: paramLiteral,
				Threshold:     ts.T,
			}

			lt, err := NewLocalTest(LocalTestConfig{
				PeerNodes:     ts.N,
				SessionParams: &sessParams,
			})
			require.Nil(t, err)

			testSess := lt.TestSession

			all, clients, cloud := NewTestNodes(lt)
			for _, cli := range clients {
				cid := cli.id
				cli.InputProvider = func(ctx context.Context, _ helium.CircuitID, ol circuit.OperandLabel, _ session.Session) (any, error) {
					return NodeIDtoTestInput(string(cid)), nil
				}
			}

			ctx := helium.NewBackgroundContext(sessParams.ID)
			hid := cloud.id

			app := App{
				SetupDescription: &testSetupDescription,
				Circuits:         circuit.TestCircuits,
			}

			g, runctx := errgroup.WithContext(ctx)

			var cdescs = make(chan chan<- circuit.Descriptor)
			for _, node := range all {
				node := node
				g.Go(func() error {
					cdescsn, outs, err := node.Run(runctx, app, node.InputProvider, lt.coordinator, lt.transport.TransportFor(node.id))
					if err != nil {
						return err
					}
					if node.id == hid {
						cdescs <- cdescsn
					}
					for out := range outs {
						node.Outputs[out.CircuitID] = out
					}
					return nil
				})
			}

			nodemap := map[string]helium.NodeID{"p1": "peer-0", "p2": "peer-1", "eval": "helper", "rec": ts.Reciever}
			cdesc := <-cdescs
			expResult := make(map[helium.CircuitID]uint64)
			for _, tc := range ts.CircuitSigs {
				for i := 0; i < ts.Rep; i++ {
					cid := helium.CircuitID(fmt.Sprintf("%s-%d", tc.Name, i))
					cdesc <- circuit.Descriptor{Signature: circuit.Signature{Name: tc.Name}, CircuitID: cid, NodeMapping: nodemap, Evaluator: hid}
					expResult[cid] = tc.ExpResult
				}
			}

			close(cdesc)
			err = g.Wait()
			if err != nil {
				t.Fatal(err)
			}

			// for _, node := range all {
			// 	netStats := node.GetNetworkStats()
			// 	require.NotZero(t, netStats.DataRecv, "node %s should have received data", node.id)
			// 	require.NotZero(t, netStats.DataSent, "node %s should have sent data", node.id)
			// }

			bgvParams, err := bgv.NewParameters(testSess.RlweParams, paramLiteral.PlaintextModulus)
			require.Nil(t, err)
			encoder := bgv.NewEncoder(bgvParams)

			rec := all[ts.Reciever]
			for cid, expRes := range expResult {
				out, has := rec.Outputs[cid]
				require.True(t, has, "reciever should have an output")
				delete(rec.Outputs, cid)
				pt := &rlwe.Plaintext{Element: out.Ciphertext.Element, Value: out.Ciphertext.Value[0]}
				res := make([]uint64, bgvParams.MaxSlots())
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
