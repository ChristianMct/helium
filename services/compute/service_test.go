package compute

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/circuits"
	"github.com/ChristianMct/helium/coordinator"
	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/session"
	"github.com/ChristianMct/helium/utils"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
	"golang.org/x/sync/errgroup"
)

var TestPN12QP109 = bgv.ParametersLiteral{
	LogN:             12,
	Q:                []uint64{0x7ffffffec001, 0x400000008001}, // 47 + 46 bits
	P:                []uint64{0xa001},                         // 15 bits
	PlaintextModulus: 65537,
}

var rangeParam = []bgv.ParametersLiteral{TestPN12QP109 /* rlwe.TestPN13QP218 , rlwe.TestPN14QP438, rlwe.TestPN15QP880*/}

type TestCircuitSig struct {
	circuits.Signature
	ExpResult uint64
}

type testSetting struct {
	N           int // N - total parties
	T           int // T - parties in the access structure
	CircuitSigs []TestCircuitSig
	Reciever    helium.NodeID
	Rep         int // numer of repetition for each circuit
}

var testNodeMapping = map[string]helium.NodeID{"p1": "node-0", "p2": "node-1", "eval": "helper"}

var testCircuitSigs = []TestCircuitSig{
	{Signature: circuits.Signature{Name: "add-2-dec", Args: nil}, ExpResult: 1},
	{Signature: circuits.Signature{Name: "mul-2-dec", Args: nil}, ExpResult: 0},
}

func NodeIDtoTestInput(nid string) []uint64 {
	num := strings.Trim(string(nid), "node-")
	i, err := strconv.ParseUint(num, 10, 64)
	if err != nil {
		panic(err)
	}
	return []uint64{i}
}

var testSettings = []testSetting{
	{N: 2, CircuitSigs: testCircuitSigs, Reciever: "node-0"},
	{N: 2, CircuitSigs: testCircuitSigs, Reciever: "helper"},
	{N: 3, T: 2, CircuitSigs: testCircuitSigs, Reciever: "node-0"},
	{N: 3, T: 2, CircuitSigs: testCircuitSigs, Reciever: "helper"},
	{N: 3, T: 2, CircuitSigs: testCircuitSigs, Reciever: "helper", Rep: 10},
}

type testnode struct {
	*Service
	coordinator.Coordinator
	InputProvider
	*session.Session

	OutputReceiver chan circuits.Output
	Outputs        map[helium.CircuitID]circuits.Output
}

type testNodeTrans struct {
	protocols.Transport
	helperSrv *Service
}

func (tnt *testNodeTrans) PutCiphertext(ctx context.Context, ct helium.Ciphertext) error {
	return tnt.helperSrv.PutCiphertext(ctx, ct)
}

func (tnt *testNodeTrans) GetCiphertext(ctx context.Context, ctID helium.CiphertextID) (*helium.Ciphertext, error) {
	return tnt.helperSrv.GetCiphertext(ctx, ctID)
}

func TestCloudAssistedCompute(t *testing.T) {
	for _, literalParams := range rangeParam {
		for _, ts := range testSettings {
			if ts.T == 0 {
				ts.T = ts.N
			}

			if ts.Rep == 0 {
				ts.Rep = 1
			}

			t.Run(fmt.Sprintf("NParty=%d/T=%d/rec=%s/rep=%d", ts.N, ts.T, ts.Reciever, ts.Rep), func(t *testing.T) {

				hid := helium.NodeID("helper")

				testSess, err := session.NewTestSession(ts.N, ts.T, literalParams, hid)
				if err != nil {
					t.Fatal(err)
				}
				sessParams := testSess.SessParams

				ctx := helium.NewBackgroundContext(sessParams.ID)

				nids := utils.NewSet(sessParams.Nodes)

				coord := coordinator.NewTestCoordinator()
				protoTrans := protocols.NewTestTransport()

				all := make(map[helium.NodeID]*testnode, ts.N+1)
				clou := new(testnode)
				all["helper"] = clou

				conf := ServiceConfig{
					CircQueueSize:        300,
					MaxCircuitEvaluation: 5,
					Protocols: protocols.ExecutorConfig{
						SigQueueSize:     300,
						MaxProtoPerNode:  1,
						MaxAggregation:   1,
						MaxParticipation: 1,
					},
				}

				srvTrans := &testNodeTrans{Transport: protoTrans}
				clou.Coordinator = coord
				clou.Service, err = NewComputeService(hid, testSess.HelperSession, conf, testSess, srvTrans)
				if err != nil {
					t.Fatal(err)
				}
				clou.OutputReceiver = make(chan circuits.Output)
				clou.Outputs = make(map[helium.CircuitID]circuits.Output)

				clients := make(map[helium.NodeID]*testnode, ts.N)
				for nid := range nids {
					nid := nid
					cli := new(testnode)
					cli.Session = testSess.NodeSessions[nid]
					srvTrans := &testNodeTrans{Transport: protoTrans.TransportFor(nid), helperSrv: clou.Service}
					cli.Service, err = NewComputeService(nid, testSess.NodeSessions[nid], conf, testSess, srvTrans)
					if err != nil {
						t.Fatal(err)
					}
					cli.Coordinator = coord.NewPeerCoordinator(nid)

					require.Nil(t, err)
					cli.InputProvider = func(ctx context.Context, _ helium.CircuitID, ol circuits.OperandLabel, _ session.Session) (any, error) {
						return NodeIDtoTestInput(string(nid)), nil
					}
					cli.OutputReceiver = make(chan circuits.Output)
					cli.Outputs = make(map[helium.CircuitID]circuits.Output)
					clou.Executor.Register(nid)
					clients[nid] = cli
					all[nid] = cli
				}

				for _, n := range all {
					err = n.RegisterCircuits(circuits.TestCircuits)
					require.Nil(t, err)
				}

				g, ctx := errgroup.WithContext(ctx)
				// run the nodes
				for nid, node := range all {
					nid := nid
					cli := node
					g.Go(func() error {
						for out := range cli.OutputReceiver {
							cli.Outputs[out.CircuitID] = out
						}
						return nil
					})
					g.Go(func() error {
						return errors.WithMessage(
							cli.Service.Run(ctx, cli.InputProvider, cli.OutputReceiver, cli.Coordinator),
							fmt.Sprintf("at node %s", nid))
					})
				}

				cds := make([]circuits.Descriptor, 0, len(ts.CircuitSigs)*ts.Rep)
				expResult := make(map[helium.CircuitID]uint64)
				for _, tc := range ts.CircuitSigs {
					for r := 0; r < ts.Rep; r++ {
						cid := helium.CircuitID(fmt.Sprintf("%s-%d", tc.Name, r))
						cd := circuits.Descriptor{
							Signature:   tc.Signature,
							CircuitID:   cid,
							NodeMapping: testNodeMapping,
							Evaluator:   "helper",
						}
						cd.NodeMapping["rec"] = ts.Reciever
						cds = append(cds, cd)
						expResult[cid] = tc.ExpResult
					}
				}

				for _, cd := range cds {
					coord.LogEvent(coordinator.Event{CircuitEvent: &circuits.Event{EventType: circuits.Started, Descriptor: cd}})
				}
				coord.Close()

				err = g.Wait() // waits for all parties to terminate
				require.Nil(t, err)

				bgvParams, err := bgv.NewParameters(testSess.RlweParams, literalParams.PlaintextModulus)
				require.Nil(t, err)
				encoder := bgv.NewEncoder(bgvParams)

				fmt.Println("all done")
				rec := all[ts.Reciever]
				for cid, expRes := range expResult {
					out, has := rec.Outputs[cid]
					require.True(t, has, "reciever should have an output")
					delete(rec.Outputs, cid)
					pt := &rlwe.Plaintext{Element: out.Ciphertext.Element, Value: out.Ciphertext.Value[0]}
					pt.IsNTT = true
					res := make([]uint64, bgvParams.MaxSlots())
					err := encoder.Decode(pt, res)
					require.Nil(t, err)
					fmt.Println(out.OperandLabel, res[:10])
					require.Equal(t, expRes, res[0])
				}

				for nid, n := range all {
					require.Empty(t, n.Outputs, "node %s should have no extra outputs", nid)
				}

			})
		}
	}
}
