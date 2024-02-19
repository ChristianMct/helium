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
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v4/bgv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

var TestPN12QP109 = bgv.ParametersLiteral{
	LogN: 12,
	Q:    []uint64{0x7ffffffec001, 0x400000008001}, // 47 + 46 bits
	P:    []uint64{0xa001},                         // 15 bits
	T:    65537,
}

var rangeParam = []bgv.ParametersLiteral{TestPN12QP109 /* rlwe.TestPN13QP218 , rlwe.TestPN14QP438, rlwe.TestPN15QP880*/}

type testSetting struct {
	N int // N - total parties
	T int // T - parties in the access structure
}

var testSettings = []testSetting{
	{N: 2},
	{N: 3},
	{N: 3, T: 2},
}

type testnode struct {
	*Service
	*pkg.Session
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
	return []uint64{i, i, i}
}

func TestCloudAssistedCompute(t *testing.T) {
	for _, literalParams := range rangeParam {
		for _, ts := range testSettings {
			if ts.T == 0 {
				ts.T = ts.N
			}

			t.Run(fmt.Sprintf("NParty=%d/T=%d/logN=%d", ts.N, ts.T, literalParams.LogN), func(t *testing.T) {

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

				clou := new(testnode)

				srvTrans := &testNodeTrans{Transport: protoTrans}
				clou.Service, err = NewComputeService(hid, testSess.HelperSession, testSess, srvTrans)
				if err != nil {
					t.Fatal(err)
				}
				clou.Service.Run(ctx, NoInput, coord)

				clients := make(map[pkg.NodeID]*testnode, ts.N)
				for nid := range nids {
					cli := &testnode{}
					cli.Session = testSess.NodeSessions[nid]
					srvTrans := &testNodeTrans{Transport: protoTrans.TransportFor(nid), helperSrv: clou.Service}
					cli.Service, err = NewComputeService(nid, testSess.NodeSessions[nid], testSess, srvTrans)
					if err != nil {
						t.Fatal(err)
					}

					pt := rlwe.NewPlaintext(testSess.RlweParams, testSess.RlweParams.MaxLevel())
					testSess.Encoder.Encode(nodeIDtoInput(nid), pt)

					var ip InputProvider = func(ctx context.Context, ol circuits.OperandLabel) (*rlwe.Plaintext, error) {
						return pt, nil
					}

					cli.Service.Run(ctx, ip, coord.NewNodeCoordinator(nid))
					clou.Executor.Register(nid)
					clients[nid] = cli
				}

				cName := circuits.Name("add-2")
				var c circuits.Circuit = func(ec circuits.EvaluationContext) error {

					in1, in2 := ec.Input("//p1/in"), ec.Input("//p2/in")

					opRes := ec.NewOperand("//eval/sum")
					opRes.Ciphertext = bgv.NewCiphertext(ec.Parameters(), 1, ec.Parameters().MaxLevel())
					ec.Add(in1.Get().Ciphertext, in2.Get().Ciphertext, opRes.Ciphertext)

					params := ec.Parameters().Parameters
					opOut, err := ec.DEC(opRes, map[string]string{
						"target":   "eval",
						"lvl":      strconv.Itoa(params.MaxLevel()),
						"smudging": "40.0",
					})
					if err != nil {
						return err
					}

					ec.Output(opOut.Get(), "eval")
					return nil
				}

				err = clou.Service.RegisterCircuit(cName, c)
				require.Nil(t, err)
				for _, cli := range clients {
					err = cli.Service.RegisterCircuit(cName, c)
					require.Nil(t, err)
				}

				cd := circuits.Descriptor{
					Signature:    circuits.Signature{Name: cName},
					ID:           circuits.ID(fmt.Sprintf("%s-%d", cName, 1)),
					InputParties: map[string]pkg.NodeID{"p1": "node-0", "p2": "node-1", "eval": "helper"},
					Evaluator:    hid,
				}
				outs, err := clou.Service.RunCircuit(ctx, cd)
				require.Nil(t, err)

				for out := range outs {
					require.NotNil(t, out.Ciphertext)
					fmt.Printf("recieved output op: %s\n", out.OperandLabel)
					pt := &rlwe.Plaintext{Operand: out.Ciphertext.Operand, Value: out.Ciphertext.Value[0]} //testSess.Decrpytor.DecryptNew(out.Ciphertext)
					res := make([]uint64, testSess.RlweParams.PlaintextSlots())
					testSess.Encoder.Decode(pt, res)
					fmt.Println(res[:10])
				}

			})
		}
	}
}
