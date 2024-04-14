package compute

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/circuit"
	"github.com/ChristianMct/helium/coord"
	"github.com/ChristianMct/helium/protocol"
	"github.com/ChristianMct/helium/session"
	"github.com/ChristianMct/helium/utils"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
	"github.com/tuneinsight/lattigo/v5/schemes/ckks"
	"golang.org/x/sync/errgroup"
)

type TestCircuitSig struct {
	circuit.Signature
	ExpResult interface{}
}

type testSetting struct {
	N        int // N - total parties
	T        int // T - parties in the access structure
	Reciever helium.NodeID
	Rep      int // numer of repetition for each circuit
}

var testNodeMapping = map[string]helium.NodeID{"p1": "node-0", "p2": "node-1", "eval": "helper"}

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
	*session.Session

	OutputReceiver chan circuit.Output
	Outputs        map[helium.CircuitID]circuit.Output
}

type testNodeTrans struct {
	protocol.Transport
	helperSrv *Service
}

func (tnt *testNodeTrans) PutCiphertext(ctx context.Context, ct helium.Ciphertext) error {
	return tnt.helperSrv.PutCiphertext(ctx, ct)
}

func (tnt *testNodeTrans) GetCiphertext(ctx context.Context, ctID helium.CiphertextID) (*helium.Ciphertext, error) {
	return tnt.helperSrv.GetCiphertext(ctx, ctID)
}

func TestCloudAssistedComputeBGV(t *testing.T) {

	bgvParamsLiteral := bgv.ParametersLiteral{
		LogN:             12,
		Q:                []uint64{0x7ffffffec001, 0x400000008001}, // 47 + 46 bits
		P:                []uint64{0xa001},                         // 15 bits
		PlaintextModulus: 65537,
	}

	var testCircuitSigs = []TestCircuitSig{
		{Signature: circuit.Signature{Name: "bgv-add-2-dec", Args: nil}, ExpResult: uint64(3)},
		{Signature: circuit.Signature{Name: "bgv-mul-2-dec", Args: nil}, ExpResult: uint64(2)},
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

			hid := helium.NodeID("helper")

			testSess, err := session.NewTestSession(ts.N, ts.T, bgvParamsLiteral, hid)
			if err != nil {
				t.Fatal(err)
			}
			sessParams := testSess.SessParams

			ctx := helium.NewBackgroundContext(sessParams.ID)

			nids := utils.NewSet(sessParams.Nodes)

			coord := coord.NewTestCoordinator[Event](hid)
			protoTrans := protocol.NewTestTransport()

			all := make(map[helium.NodeID]*testnode, ts.N+1)
			clou := new(testnode)
			all["helper"] = clou

			conf := ServiceConfig{
				CircQueueSize:        300,
				MaxCircuitEvaluation: 5,
				Protocols: protocol.ExecutorConfig{
					SigQueueSize:     300,
					MaxProtoPerNode:  1,
					MaxAggregation:   1,
					MaxParticipation: 1,
				},
			}

			srvTrans := &testNodeTrans{Transport: protoTrans}
			clou.Service, err = NewComputeService(hid, testSess.HelperSession, conf, testSess, srvTrans)
			if err != nil {
				t.Fatal(err)
			}
			clou.OutputReceiver = make(chan circuit.Output)
			clou.Outputs = make(map[helium.CircuitID]circuit.Output)

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

				require.Nil(t, err)
				cli.InputProvider = func(ctx context.Context, _ helium.CircuitID, ol circuit.OperandLabel, _ session.Session) (any, error) {
					return nodeIDtoTestInput(string(nid)), nil
				}
				cli.OutputReceiver = make(chan circuit.Output)
				cli.Outputs = make(map[helium.CircuitID]circuit.Output)
				clou.Executor.Register(nid)
				clients[nid] = cli
				all[nid] = cli
			}

			for _, n := range all {
				err = n.RegisterCircuits(circuit.TestCircuits)
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
						cli.Service.Run(ctx, cli.InputProvider, cli.OutputReceiver, coord),
						fmt.Sprintf("at node %s", nid))
				})
			}

			cds := make([]circuit.Descriptor, 0, len(testCircuitSigs)*ts.Rep)
			expResult := make(map[helium.CircuitID]uint64)
			for _, tc := range testCircuitSigs {
				for r := 0; r < ts.Rep; r++ {
					cid := helium.CircuitID(fmt.Sprintf("%s-%d", tc.Name, r))
					cd := circuit.Descriptor{
						Signature:   tc.Signature,
						CircuitID:   cid,
						NodeMapping: testNodeMapping,
						Evaluator:   "helper",
					}
					cd.NodeMapping["rec"] = ts.Reciever
					cds = append(cds, cd)
					expResult[cid] = tc.ExpResult.(uint64)
				}
			}

			for _, cd := range cds {
				err = clou.EvalCircuit(ctx, cd)
				require.Nil(t, err)
			}
			coord.Close()

			err = g.Wait() // waits for all parties to terminate
			require.Nil(t, err)

			bgvParams, err := bgv.NewParameters(testSess.RlweParams, bgvParamsLiteral.PlaintextModulus)
			require.Nil(t, err)
			encoder := bgv.NewEncoder(bgvParams)

			//fmt.Println("all done")
			rec := all[ts.Reciever]
			for cid, expRes := range expResult {
				out, has := rec.Outputs[cid]
				require.True(t, has, "reciever should have an output")
				delete(rec.Outputs, cid)
				pt := &rlwe.Plaintext{Element: out.Ciphertext.Element, Value: out.Ciphertext.Value[0]}
				pt.IsNTT = out.Ciphertext.IsNTT
				res := make([]uint64, bgvParams.MaxSlots())
				err := encoder.Decode(pt, res)
				require.Nil(t, err)
				//fmt.Println(out.OperandLabel, res[:10])
				require.Equal(t, expRes, res[0])
			}

			for nid, n := range all {
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

	var testCircuitSigs = []TestCircuitSig{
		{Signature: circuit.Signature{Name: "ckks-add-2-dec", Args: nil}, ExpResult: 1.0},
		{Signature: circuit.Signature{Name: "ckks-mul-2-dec", Args: nil}, ExpResult: 0.2222222222222222},
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

			hid := helium.NodeID("helper")

			testSess, err := session.NewTestSession(ts.N, ts.T, ckksParamsLiteral, hid)
			if err != nil {
				t.Fatal(err)
			}
			sessParams := testSess.SessParams

			ctx := helium.NewBackgroundContext(sessParams.ID)

			nids := utils.NewSet(sessParams.Nodes)

			tc := coord.NewTestCoordinator[Event](hid)
			protoTrans := protocol.NewTestTransport()

			all := make(map[helium.NodeID]*testnode, ts.N+1)
			clou := new(testnode)
			all["helper"] = clou

			conf := ServiceConfig{
				CircQueueSize:        300,
				MaxCircuitEvaluation: 5,
				Protocols: protocol.ExecutorConfig{
					SigQueueSize:     300,
					MaxProtoPerNode:  1,
					MaxAggregation:   1,
					MaxParticipation: 1,
				},
			}

			srvTrans := &testNodeTrans{Transport: protoTrans}
			clou.Service, err = NewComputeService(hid, testSess.HelperSession, conf, testSess, srvTrans)
			if err != nil {
				t.Fatal(err)
			}
			clou.OutputReceiver = make(chan circuit.Output)
			clou.Outputs = make(map[helium.CircuitID]circuit.Output)

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

				require.Nil(t, err)
				cli.InputProvider = func(ctx context.Context, _ helium.CircuitID, ol circuit.OperandLabel, _ session.Session) (any, error) {
					return nodeIDtoTestInput(string(nid)), nil
				}
				cli.OutputReceiver = make(chan circuit.Output)
				cli.Outputs = make(map[helium.CircuitID]circuit.Output)
				clou.Executor.Register(nid)
				clients[nid] = cli
				all[nid] = cli
			}

			for _, n := range all {
				err = n.RegisterCircuits(circuit.TestCircuits)
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
						cli.Service.Run(ctx, cli.InputProvider, cli.OutputReceiver, tc),
						fmt.Sprintf("at node %s", nid))
				})
			}

			cds := make([]circuit.Descriptor, 0, len(testCircuitSigs)*ts.Rep)
			expResult := make(map[helium.CircuitID]float64)
			for _, tc := range testCircuitSigs {
				for r := 0; r < ts.Rep; r++ {
					cid := helium.CircuitID(fmt.Sprintf("%s-%d", tc.Name, r))
					cd := circuit.Descriptor{
						Signature:   tc.Signature,
						CircuitID:   cid,
						NodeMapping: testNodeMapping,
						Evaluator:   "helper",
					}
					cd.NodeMapping["rec"] = ts.Reciever
					cds = append(cds, cd)
					expResult[cid] = tc.ExpResult.(float64)
				}
			}

			for _, cd := range cds {
				err = clou.EvalCircuit(ctx, cd)
				require.Nil(t, err)
			}
			tc.Close()

			err = g.Wait() // waits for all parties to terminate
			require.Nil(t, err)

			ckksParams, err := ckks.NewParametersFromLiteral(ckksParamsLiteral)
			require.Nil(t, err)
			encoder := ckks.NewEncoder(ckksParams)

			//fmt.Println("all done")
			rec := all[ts.Reciever]
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
				//fmt.Printf("%s: exp=%.4f res=%.4f\n", out.OperandLabel, expRes, res[0])
				require.InDelta(t, expRes, res[0], 0.0001) // TODO better bounds
			}

			for nid, n := range all {
				require.Empty(t, n.Outputs, "node %s should have no extra outputs", nid)
			}

		})
	}
}
