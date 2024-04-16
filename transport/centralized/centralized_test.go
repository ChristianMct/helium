package centralized

import (
	"context"
	"fmt"
	"log"
	"net"
	"testing"
	"time"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/circuit"
	"github.com/ChristianMct/helium/node"
	"github.com/ChristianMct/helium/services/compute"
	"github.com/ChristianMct/helium/services/setup"
	"github.com/ChristianMct/helium/session"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v5/he/heint"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/test/bufconn"
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

			params, err := heint.NewParametersFromLiteral(heint.ParametersLiteral{LogN: 12, LogQ: []int{45, 45}, LogP: []int{19}, PlaintextModulus: 79873}) // matmul
			require.Nil(t, err)
			sessParams := session.Parameters{
				ID:            "test-session",
				FHEParameters: params.ParametersLiteral(),
				Threshold:     ts.T,
			}

			lt, err := node.NewLocalTest(node.LocalTestConfig{
				PeerNodes:     ts.N,
				SessionParams: &sessParams,
			})
			require.Nil(t, err)

			testSess := lt.TestSession

			ctx := helium.NewBackgroundContext(sessParams.ID)

			app := node.App{
				SetupDescription: &testSetupDescription,
			}

			helper := NewHeliumServer(lt.HelperNode)
			clients := make([]*HeliumClient, ts.N)
			for i := 0; i < ts.N; i++ {
				clients[i] = NewHeliumClient(lt.PeerNodes[i], lt.HelperNode.ID(), lt.HelperNode.Address())
			}

			lis := bufconn.Listen(buffConBufferSize)
			go helper.Serve(lis)

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

			n := 0
			for _, cli := range clients {
				cli := cli

				g.Go(func() error {

					if n >= ts.T {
						<-time.After(time.Second)
					}
					n++

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

			setup.CheckTestSetup(ctx, t, testSess, *app.SetupDescription, helper)

			for _, cli := range clients {
				log.Println("checking setup for", cli.id)
				resCheckCtx, runCheckCancel := context.WithTimeout(ctx, time.Second)
				setup.CheckTestSetup(resCheckCtx, t, testSess, *app.SetupDescription, cli)
				runCheckCancel()

				require.NoError(t, cli.Close())
			}

			helper.Server.GracefulStop()
		})
	}
}
