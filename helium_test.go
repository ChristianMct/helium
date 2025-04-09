package helium

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ChristianMct/helium/circuits"
	"github.com/ChristianMct/helium/node"
	"github.com/ChristianMct/helium/services/compute"
	"github.com/ChristianMct/helium/services/setup"
	"github.com/ChristianMct/helium/sessions"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/test/bufconn"
)

type TestCircuitSig struct {
	circuits.Signature
	ExpResult uint64
}

var testSessionParameters = sessions.Parameters{
	ID:            "test-session",
	FHEParameters: bgv.ParametersLiteral{LogN: 12, LogQ: []int{45, 45}, LogP: []int{19}, PlaintextModulus: 79873},
	// Threshold:     set by test
}

type testSetting struct {
	N           int // N - total parties
	T           int // T - parties in the access structure
	CircuitSigs []TestCircuitSig
	Reciever    sessions.NodeID
	Rep         int // numer of repetition for each circuit
}

var testSetupDescription = setup.Description{
	Cpk: true,
	Rlk: true,
	Gks: []uint64{5, 25, 125},
}

var testCircuits2P = []TestCircuitSig{
	{Signature: circuits.Signature{Name: "bgv-add-2-dec", Args: nil}, ExpResult: 1},
	{Signature: circuits.Signature{Name: "bgv-mul-2-dec", Args: nil}, ExpResult: 0},
	{Signature: circuits.Signature{Name: "bgv-add-n-dec", Args: map[string]string{"n": "2"}}, ExpResult: 1},
}

var testCircuits3P = []TestCircuitSig{
	{Signature: circuits.Signature{Name: "bgv-add-2-dec", Args: nil}, ExpResult: 1},
	{Signature: circuits.Signature{Name: "bgv-mul-2-dec", Args: nil}, ExpResult: 0},
	{Signature: circuits.Signature{Name: "bgv-add-n-dec", Args: map[string]string{"n": "2"}}, ExpResult: 1},
	{Signature: circuits.Signature{Name: "bgv-add-n-dec", Args: map[string]string{"n": "3"}}, ExpResult: 3},
}

var testSettings = []testSetting{
	{N: 2, CircuitSigs: testCircuits2P, Reciever: "peer-0"},
	{N: 2, CircuitSigs: testCircuits2P, Reciever: "helper"},
	{N: 3, T: 2, CircuitSigs: testCircuits3P, Reciever: "peer-0"},
	{N: 3, T: 2, CircuitSigs: testCircuits3P, Reciever: "helper"},
	{N: 3, T: 2, CircuitSigs: testCircuits3P, Reciever: "helper", Rep: 10},
}

const buffConBufferSize = 65 * 1024 * 1024

func TestSetup(t *testing.T) {
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
			lt, err := node.NewLocalTest(node.LocalTestConfig{
				PeerNodes:     ts.N,
				SessionParams: &sessParams,
			})
			require.Nil(t, err)

			app := node.App{
				SetupDescription: &testSetupDescription,
			}

			helper := NewHeliumServer(lt.HelperNode)
			clients := make([]*HeliumClient, ts.N)
			for i := 0; i < ts.N; i++ {
				clients[i] = NewHeliumClient(lt.PeerNodes[i], lt.HelperNode.ID(), "local")
			}

			lis := bufconn.Listen(buffConBufferSize)
			go helper.Serve(lis)

			ctx := sessions.NewBackgroundContext(sessParams.ID)
			g, runctx := errgroup.WithContext(ctx)
			g.Go(func() error {
				cdescs, outs, err := helper.Run(runctx, app, compute.NoInput)
				if err != nil {
					return err
				}
				close(cdescs)
				_, has := <-outs
				if has {
					return fmt.Errorf("%s should have no output", helper.id)
				}
				return nil
			})

			for _, cli := range clients {
				cli := cli

				g.Go(func() error {
					err = cli.ConnectWithDialer(func(c context.Context, addr string) (net.Conn, error) { return lis.Dial() })
					if err != nil {
						return fmt.Errorf("node %s failed to connect: %v", cli.id, err)
					}

					outs, err := cli.Run(runctx, app, compute.NoInput)
					if err != nil {
						return err
					}
					_, has := <-outs
					if has {
						return fmt.Errorf("%s should have no output", cli.id)
					}
					return nil
				})
			}

			err = g.Wait()
			if err != nil {
				t.Fatal(err)
			}

			setup.CheckTestSetup(ctx, t, *app.SetupDescription, helper, lt.RlweParams, lt.SkIdeal, ts.N)

			for _, cli := range clients {
				log.Println("checking setup for", cli.id)
				resCheckCtx, runCheckCancel := context.WithTimeout(ctx, time.Second)
				setup.CheckTestSetup(resCheckCtx, t, *app.SetupDescription, cli, lt.RlweParams, lt.SkIdeal, ts.N)
				runCheckCancel()

				require.NoError(t, cli.Close())
			}

			helper.Server.GracefulStop()
		})
	}
}

func TestCompute(t *testing.T) {
	for _, ts := range testSettings {
		if ts.T == 0 {
			ts.T = ts.N
		}
		if ts.Rep == 0 {
			ts.Rep = 1
		}

		nodemap := map[string]sessions.NodeID{"p1": "peer-0", "p2": "peer-1", "p3": "peer-2", "eval": "helper", "rec": ts.Reciever}

		expResult := make(map[sessions.CircuitID]uint64)
		for i, tc := range ts.CircuitSigs {
			for rep := 0; rep < ts.Rep; rep++ {
				cid := sessions.CircuitID(fmt.Sprintf("%s-%d-%d", tc.Name, i, rep))
				expResult[cid] = tc.ExpResult
			}
		}

		t.Run(fmt.Sprintf("NParty=%d/T=%d/rec=%s/rep=%d", ts.N, ts.T, ts.Reciever, ts.Rep), func(t *testing.T) {

			sessParams := testSessionParameters
			sessParams.Threshold = ts.T
			lt, err := node.NewLocalTest(node.LocalTestConfig{
				PeerNodes:     ts.N,
				SessionParams: &sessParams,
			})
			require.Nil(t, err)

			app := node.App{
				SetupDescription: &testSetupDescription,
				Circuits:         circuits.TestCircuits,
			}

			helper := NewHeliumServer(lt.HelperNode)
			clients := make([]*HeliumClient, ts.N)
			for i := 0; i < ts.N; i++ {
				clients[i] = NewHeliumClient(lt.PeerNodes[i], lt.HelperNode.ID(), "local")
			}

			lis := bufconn.Listen(buffConBufferSize)
			go helper.Serve(lis)

			testOuts := make(chan struct {
				sessions.NodeID
				circuits.Output
			}, len(expResult))

			ctx := sessions.NewBackgroundContext(sessParams.ID)
			g, runctx := errgroup.WithContext(ctx)
			g.Go(func() error {
				cdescs, outs, err := helper.Run(runctx, app, compute.NoInput)
				if err != nil {
					return err
				}

				go func() {
					for i, tc := range ts.CircuitSigs {
						for rep := 0; rep < ts.Rep; rep++ {
							cid := sessions.CircuitID(fmt.Sprintf("%s-%d-%d", tc.Name, i, rep))
							cdescs <- circuits.Descriptor{Signature: tc.Signature, CircuitID: cid, NodeMapping: nodemap, Evaluator: helper.id}
						}
					}
					close(cdescs)
				}()

				for out := range outs {
					testOuts <- struct {
						sessions.NodeID
						circuits.Output
					}{helper.id, out}
				}

				return nil
			})

			for _, cli := range clients {
				cli := cli

				g.Go(func() error {
					err = cli.ConnectWithDialer(func(c context.Context, addr string) (net.Conn, error) { return lis.Dial() })
					if err != nil {
						return fmt.Errorf("node %s failed to connect: %v", cli.id, err)
					}

					ip := func(ctx context.Context, _ sessions.CircuitID, ol circuits.OperandLabel, _ sessions.Session) (any, error) {
						return nodeIDtoTestInput(string(cli.id)), nil
					}

					outs, err := cli.Run(runctx, app, ip)
					if err != nil {
						return err
					}

					for out := range outs {
						testOuts <- struct {
							sessions.NodeID
							circuits.Output
						}{cli.id, out}
					}
					return nil
				})
			}

			err = g.Wait()
			close(testOuts)

			encoder := bgv.NewEncoder(lt.Params)
			for out := range testOuts {
				require.Equal(t, out.NodeID, ts.Reciever)
				pt := &rlwe.Plaintext{Element: out.Ciphertext.Element, Value: out.Ciphertext.Value[0]}
				res := make([]uint64, lt.Params.MaxSlots())
				err = encoder.Decode(pt, res)
				//fmt.Println(out.OperandLabel, res[:10])
				require.NoError(t, err)
				exp, has := expResult[out.CircuitID]
				require.True(t, has, "unexpected result for %s", out.CircuitID)
				require.Equal(t, exp, res[0])
				delete(expResult, out.CircuitID)
			}

			require.Empty(t, expResult, "not all expected results were received")

			if err != nil {
				t.Fatal(err)
			}

			helper.Server.GracefulStop()
		})
	}
}

func nodeIDtoTestInput(nid string) []uint64 {
	num := strings.Trim(string(nid), "per-")
	i, err := strconv.ParseUint(num, 10, 64)
	if err != nil {
		panic(err)
	}
	return []uint64{i}
}
