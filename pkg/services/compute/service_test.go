package compute

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/ldsec/helium/pkg/circuits"
	"github.com/ldsec/helium/pkg/coordinator"
	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/protocols"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v4/bgv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"golang.org/x/sync/errgroup"
)

var TestPN12QP109 = bgv.ParametersLiteral{
	LogN: 12,
	Q:    []uint64{0x7ffffffec001, 0x400000008001}, // 47 + 46 bits
	P:    []uint64{0xa001},                         // 15 bits
	T:    65537,
}

var rangeParam = []bgv.ParametersLiteral{TestPN12QP109 /* rlwe.TestPN13QP218 , rlwe.TestPN14QP438, rlwe.TestPN15QP880*/}

type TestCircuit struct {
	circuits.Signature
	ExpResult uint64
}

type testSetting struct {
	N        int // N - total parties
	T        int // T - parties in the access structure
	Circuits []TestCircuit
	Reciever pkg.NodeID
	Rep      int // numer of repetition for each circuit
}

var testNodeMapping = map[string]pkg.NodeID{"p1": "node-0", "p2": "node-1", "eval": "helper"}

var testCircuits = []TestCircuit{
	{Signature: circuits.Signature{Name: "add-2-dec", Args: nil}, ExpResult: 1},
	//{Descriptor: circuits.Descriptor{Signature: circuits.Signature{Name: "add-2-dec", Args: nil}, ID: "add-2-dec-2", Evaluator: "helper"}, ExpResult: 1},
	//{Descriptor: circuits.Descriptor{Signature: circuits.Signature{Name: "add-2-dec", Args: nil}, ID: "add-2-dec-3", Evaluator: "helper"}, ExpResult: 1},
}

var testSettings = []testSetting{
	{N: 2, Circuits: testCircuits, Reciever: "node-0"},
	{N: 2, Circuits: testCircuits, Reciever: "helper"},
	{N: 3, T: 2, Circuits: testCircuits, Reciever: "node-0"},
	{N: 3, T: 2, Circuits: testCircuits, Reciever: "helper"},
}

type testnode struct {
	*Service
	Coordinator
	InputProvider
	*pkg.Session

	OutputReceiver chan circuits.Output
	Outputs        map[circuits.ID]circuits.Output
}

type testNodeTrans struct {
	protocols.Transport
	helperSrv *Service
}

func (tnt *testNodeTrans) PutCiphertext(ctx context.Context, ct pkg.Ciphertext) error {
	return tnt.helperSrv.PutCiphertext(ctx, ct)
}

func (tnt *testNodeTrans) GetCiphertext(ctx context.Context, ctID pkg.CiphertextID) (*pkg.Ciphertext, error) {
	return tnt.helperSrv.GetCiphertext(ctx, ctID)
}

func nodeIDtoInput(nid pkg.NodeID) []uint64 {
	num := strings.Trim(string(nid), "node-")
	i, err := strconv.ParseUint(num, 10, 64)
	if err != nil {
		panic(err)
	}
	return []uint64{i}
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

			t.Run(fmt.Sprintf("NParty=%d/T=%d/rec=%s", ts.N, ts.T, ts.Reciever), func(t *testing.T) {

				hid := pkg.NodeID("helper")

				testSess, err := pkg.NewTestSession(ts.N, ts.T, literalParams, hid)
				if err != nil {
					t.Fatal(err)
				}
				sessParams := testSess.SessParams

				ctx := pkg.NewContext(&sessParams.ID, nil)

				nids := utils.NewSet(sessParams.Nodes)

				coord := coordinator.NewTestCoordinator()
				protoTrans := protocols.NewTestTransport()

				all := make(map[pkg.NodeID]*testnode, ts.N+1)
				clou := new(testnode)
				all["helper"] = clou

				srvTrans := &testNodeTrans{Transport: protoTrans}
				clou.Coordinator = coord
				clou.Service, err = NewComputeService(hid, testSess.HelperSession, testSess, srvTrans)
				if err != nil {
					t.Fatal(err)
				}
				clou.OutputReceiver = make(chan circuits.Output)
				clou.Outputs = make(map[circuits.ID]circuits.Output)

				clients := make(map[pkg.NodeID]*testnode, ts.N)
				for nid := range nids {
					cli := new(testnode)
					cli.Session = testSess.NodeSessions[nid]
					srvTrans := &testNodeTrans{Transport: protoTrans.TransportFor(nid), helperSrv: clou.Service}
					cli.Service, err = NewComputeService(nid, testSess.NodeSessions[nid], testSess, srvTrans)
					if err != nil {
						t.Fatal(err)
					}

					pt := rlwe.NewPlaintext(testSess.RlweParams, testSess.RlweParams.MaxLevel())
					testSess.Encoder.Encode(nodeIDtoInput(nid), pt)
					cli.Coordinator = coord.NewNodeCoordinator(nid)
					cli.InputProvider = func(ctx context.Context, ol circuits.OperandLabel) (*rlwe.Plaintext, error) {
						return pt, nil
					}
					cli.OutputReceiver = make(chan circuits.Output)
					cli.Outputs = make(map[circuits.ID]circuits.Output)
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
				for nid, cli := range all {
					nid := nid
					cli := cli
					g.Go(func() error {
						for out := range cli.OutputReceiver {
							cli.Outputs[out.ID] = out
						}
						return nil
					})
					g.Go(func() error {
						return errors.WithMessage(
							cli.Service.Run(ctx, cli.InputProvider, cli.OutputReceiver, cli.Coordinator),
							fmt.Sprintf("at node %s", nid))
					})
				}

				cds := make([]circuits.Descriptor, 0, len(ts.Circuits)*ts.Rep)
				expResult := make(map[circuits.ID]uint64)
				for _, tc := range ts.Circuits {
					for r := 0; r < ts.Rep; r++ {
						cid := circuits.ID(fmt.Sprintf("%s-%d", tc.Name, r))
						cd := circuits.Descriptor{
							Signature:   tc.Signature,
							ID:          cid,
							NodeMapping: testNodeMapping,
							Evaluator:   "helper",
						}
						cd.NodeMapping["rec"] = ts.Reciever
						cds = append(cds, cd)
						expResult[cid] = tc.ExpResult
					}
				}

				for _, cd := range cds {
					coord.New(coordinator.Event{CircuitEvent: &circuits.Event{Status: circuits.Executing, Descriptor: cd}})
				}
				coord.Close()

				err = g.Wait() // waits for all parties to terminate
				require.Nil(t, err)

				rec := all[ts.Reciever]
				for cid, expRes := range expResult {
					out, has := rec.Outputs[cid]
					require.True(t, has, "reciever should have an output")
					delete(rec.Outputs, cid)
					pt := &rlwe.Plaintext{Operand: out.Ciphertext.Operand, Value: out.Ciphertext.Value[0]}
					res := make([]uint64, testSess.RlweParams.PlaintextSlots())
					testSess.Encoder.Decode(pt, res)
					//fmt.Println(out.OperandLabel, res[:10])
					require.Equal(t, expRes, res[0])
				}

				for nid, n := range all {
					require.Empty(t, n.Outputs, "node %s should have no extra outputs", nid)
				}

			})
		}
	}
}
