package compute

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/ChristianMct/helium/circuits"
	"github.com/ChristianMct/helium/coordinator"
	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/sessions"
	"github.com/ChristianMct/helium/utils"
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

	OutputReceiver chan circuits.Output
	Outputs        map[sessions.CircuitID]circuits.Output
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

			hid := sessions.NodeID("helper")

			testSess, err := sessions.NewTestSession(ts.N, ts.T, bgvParamsLiteral, hid)
			if err != nil {
				t.Fatal(err)
			}
			sessParams := testSess.SessParams

			ctx := sessions.NewBackgroundContext(sessParams.ID)

			nids := utils.NewSet(sessParams.Nodes)

			all := make(map[sessions.NodeID]*testnode, ts.N+1)
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

			clou.Service, err = NewComputeService(hid, testSess.HelperSession, conf, testSess)
			if err != nil {
				t.Fatal(err)
			}
			clou.OutputReceiver = make(chan circuits.Output)
			clou.Outputs = make(map[sessions.CircuitID]circuits.Output)

			clients := make(map[sessions.NodeID]*testnode, ts.N)
			for nid := range nids {
				nid := nid
				cli := new(testnode)
				cli.Session = testSess.NodeSessions[nid]
				cli.Service, err = NewComputeService(nid, testSess.NodeSessions[nid], conf, testSess)
				if err != nil {
					t.Fatal(err)
				}

				require.Nil(t, err)
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
				cli.OutputReceiver = make(chan circuits.Output)
				cli.Outputs = make(map[sessions.CircuitID]circuits.Output)
				clou.Executor.Register(nid)
				clients[nid] = cli
				all[nid] = cli
			}

			for _, n := range all {
				err = n.RegisterCircuits(testCircuits)
				require.Nil(t, err)
			}

			tc := coordinator.NewTestCoordinator[Event](hid)
			tt := newTestTransport(clou.Service)

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
						cli.Service.Run(ctx, cli.InputProvider, cli.OutputReceiver, tc, tt.TransportFor(nid)),
						fmt.Sprintf("at node %s", nid))
				})
			}

			cds := make([]circuits.Descriptor, 0, len(testCircuitSigs)*ts.Rep)
			expResult := make(map[sessions.CircuitID]uint64)
			for _, tsig := range testCircuitSigs {
				for r := 0; r < ts.Rep; r++ {
					cid := sessions.CircuitID(fmt.Sprintf("%s-%d", tsig.Name, r))
					cd := circuits.Descriptor{
						Signature:   tsig,
						CircuitID:   cid,
						NodeMapping: testNodeMapping,
						Evaluator:   "helper",
					}
					cd.NodeMapping["rec"] = ts.Reciever
					cds = append(cds, cd)
					expResult[cid] = expRes(ts, tsig)
				}
			}

			for _, cd := range cds {
				err = clou.EvalCircuit(ctx, cd)
				require.Nil(t, err)
			}
			tc.Close()

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

	var testCircuitSigs = []circuits.Signature{
		circuits.Signature{Name: "ckks-add-2-dec", Args: nil},
		circuits.Signature{Name: "ckks-mul-2-dec", Args: nil},
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

			hid := sessions.NodeID("helper")

			testSess, err := sessions.NewTestSession(ts.N, ts.T, ckksParamsLiteral, hid)
			if err != nil {
				t.Fatal(err)
			}
			sessParams := testSess.SessParams

			ctx := sessions.NewBackgroundContext(sessParams.ID)

			nids := utils.NewSet(sessParams.Nodes)

			all := make(map[sessions.NodeID]*testnode, ts.N+1)
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

			clou.Service, err = NewComputeService(hid, testSess.HelperSession, conf, testSess)
			if err != nil {
				t.Fatal(err)
			}
			clou.OutputReceiver = make(chan circuits.Output)
			clou.Outputs = make(map[sessions.CircuitID]circuits.Output)

			clients := make(map[sessions.NodeID]*testnode, ts.N)
			for nid := range nids {
				nid := nid
				cli := new(testnode)
				cli.Session = testSess.NodeSessions[nid]
				cli.Service, err = NewComputeService(nid, testSess.NodeSessions[nid], conf, testSess)
				if err != nil {
					t.Fatal(err)
				}

				require.Nil(t, err)
				cli.InputProvider = func(ctx context.Context, sess sessions.Session, cd circuits.Descriptor) (chan circuits.Input, error) {
					in := make(chan circuits.Input, 1)
					in <- circuits.Input{OperandLabel: circuits.OperandLabel(fmt.Sprintf("//%s/%s/in", nid, cd.CircuitID)), OperandValue: nodeIDtoTestInput(string(nid))}
					close(in)
					return in, nil
				}
				cli.OutputReceiver = make(chan circuits.Output)
				cli.Outputs = make(map[sessions.CircuitID]circuits.Output)
				clou.Executor.Register(nid)
				clients[nid] = cli
				all[nid] = cli
			}

			for _, n := range all {
				err = n.RegisterCircuits(testCircuits)
				require.Nil(t, err)
			}

			tc := coordinator.NewTestCoordinator[Event](hid)
			tt := newTestTransport(clou.Service)

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
						cli.Service.Run(ctx, cli.InputProvider, cli.OutputReceiver, tc, tt.TransportFor(nid)),
						fmt.Sprintf("at node %s", nid))
				})
			}

			cds := make([]circuits.Descriptor, 0, len(testCircuitSigs)*ts.Rep)
			expResult := make(map[sessions.CircuitID]float64)
			for _, tsig := range testCircuitSigs {
				for r := 0; r < ts.Rep; r++ {
					cid := sessions.CircuitID(fmt.Sprintf("%s-%d", tsig.Name, r))
					cd := circuits.Descriptor{
						Signature:   tsig,
						CircuitID:   cid,
						NodeMapping: testNodeMapping,
						Evaluator:   "helper",
					}
					cd.NodeMapping["rec"] = ts.Reciever
					cds = append(cds, cd)
					expResult[cid] = expRes(ts, tsig)
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
