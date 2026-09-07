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
	"github.com/ChristianMct/helium/objectstore"
	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/services/compute"
	"github.com/ChristianMct/helium/sessions"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	drlwe "github.com/tuneinsight/lattigo/v5/mhe"
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

var testSetupDescription = SetupDescription{
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

// localTest is a helper + N peers test setting.
type localTest struct {
	*sessions.TestSession
	params   bgv.Parameters
	helperID sessions.NodeID
	peerIDs  []sessions.NodeID
	nl       List
	configs  map[sessions.NodeID]Config
	secrets  map[sessions.NodeID]*sessions.Secrets
}

func newLocalTest(t *testing.T, N, T int) *localTest {
	lt := &localTest{helperID: "helper", configs: make(map[sessions.NodeID]Config)}

	sp := testSessionParameters
	sp.Threshold = T
	sp.PublicSeed = []byte{'l', 'a', 't', 't', 'i', 'g', '0'}
	sp.ShamirPks = make(map[sessions.NodeID]drlwe.ShamirPublicPoint, N)
	lt.nl = List{{NodeID: lt.helperID, Address: "local"}}
	for i := 0; i < N; i++ {
		nid := sessions.NodeID("peer-" + strconv.Itoa(i))
		lt.peerIDs = append(lt.peerIDs, nid)
		sp.Nodes = append(sp.Nodes, nid)
		sp.ShamirPks[nid] = drlwe.ShamirPublicPoint(i + 1)
		lt.nl = append(lt.nl, Info{NodeID: nid})
	}

	var err error
	lt.TestSession, err = sessions.NewTestSessionFromParams(sp, lt.helperID)
	require.NoError(t, err)
	lt.secrets, err = sessions.GenTestSecretKeys(sp)
	require.NoError(t, err)

	var ok bool
	lt.params, ok = lt.FHEParameters.(bgv.Parameters)
	require.True(t, ok)

	objStore := objectstore.Config{BackendName: "mem"}
	lt.configs[lt.helperID] = Config{
		ID:                lt.helperID,
		HelperID:          lt.helperID,
		SessionParameters: []sessions.Parameters{sp},
		CoordinatorConfig: protocols.CoordinatorConfig{MaxProtoPerNode: 1},
		ComputeConfig:     compute.ServiceConfig{MaxCircuitEvaluation: 1},
		ObjectStoreConfig: objStore,
		TLSConfig:         TLSConfig{InsecureChannels: true},
	}
	for _, nid := range lt.peerIDs {
		lt.configs[nid] = Config{
			ID:                nid,
			HelperID:          lt.helperID,
			SessionParameters: []sessions.Parameters{sp},
			ProtocolsConfig:   protocols.Config{MaxParticipation: 1},
			ComputeConfig:     compute.ServiceConfig{MaxCircuitEvaluation: 1},
			ObjectStoreConfig: objStore,
			TLSConfig:         TLSConfig{InsecureChannels: true},
		}
	}
	return lt
}

func (lt *localTest) secretProvider(sid sessions.ID, nid sessions.NodeID) (*sessions.Secrets, error) {
	if sid != lt.SessParams.ID {
		return nil, fmt.Errorf("unknown session %s", sid)
	}
	sec, has := lt.secrets[nid]
	if !has {
		return nil, fmt.Errorf("no secrets for node %s", nid)
	}
	return sec, nil
}

func (lt *localTest) newServer(t *testing.T) (*HeliumServer, *bufconn.Listener) {
	helper, err := NewHeliumServer(lt.configs[lt.helperID], lt.nl)
	require.NoError(t, err)
	lis := bufconn.Listen(buffConBufferSize)
	go func() {
		if err := helper.Serve(lis); err != nil {
			log.Printf("server error: %s", err)
		}
	}()
	return helper, lis
}

func (lt *localTest) newClient(t *testing.T, nid sessions.NodeID) *HeliumClient {
	cli, err := NewHeliumClient(lt.configs[nid], lt.nl, lt.secretProvider)
	require.NoError(t, err)
	return cli
}

func bufconnDialer(lis *bufconn.Listener) Dialer {
	return func(context.Context, string) (net.Conn, error) { return lis.Dial() }
}

func TestSetup(t *testing.T) {
	for _, ts := range testSettings {
		if ts.T == 0 {
			ts.T = ts.N
		}
		if ts.Rep == 0 {
			ts.Rep = 1
		}

		t.Run(fmt.Sprintf("NParty=%d/T=%d/rec=%s/rep=%d", ts.N, ts.T, ts.Reciever, ts.Rep), func(t *testing.T) {

			lt := newLocalTest(t, ts.N, ts.T)

			app := App{
				SetupDescription: &testSetupDescription,
			}

			helper, lis := lt.newServer(t)
			clients := make([]*HeliumClient, ts.N)
			for i, nid := range lt.peerIDs {
				clients[i] = lt.newClient(t, nid)
			}

			ctx := sessions.NewBackgroundContext(lt.SessParams.ID)
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
					err := cli.ConnectWithDialer(bufconnDialer(lis))
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

			require.NoError(t, g.Wait())

			CheckTestSetup(ctx, t, *app.SetupDescription, helper, lt.RlweParams, lt.SkIdeal, ts.N)

			for _, cli := range clients {
				log.Println("checking setup for", cli.id)
				resCheckCtx, runCheckCancel := context.WithTimeout(ctx, time.Second)
				CheckTestSetup(resCheckCtx, t, *app.SetupDescription, cli, lt.RlweParams, lt.SkIdeal, ts.N)
				runCheckCancel()

				require.NoError(t, cli.Close())
			}

			helper.Server.GracefulStop()
		})
	}
}

// TestLateJoiner checks that a peer connecting after the helper has terminated the
// coordination catches up from the event log and obtains the setup keys.
func TestLateJoiner(t *testing.T) {
	ts := testSetting{N: 3, T: 2}
	lt := newLocalTest(t, ts.N, ts.T)
	app := App{SetupDescription: &testSetupDescription}

	helper, lis := lt.newServer(t)
	early := []*HeliumClient{lt.newClient(t, lt.peerIDs[0]), lt.newClient(t, lt.peerIDs[1])}
	late := lt.newClient(t, lt.peerIDs[2])

	ctx := sessions.NewBackgroundContext(lt.SessParams.ID)
	g, runctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		cdescs, outs, err := helper.Run(runctx, app, compute.NoInput)
		if err != nil {
			return err
		}
		close(cdescs)
		for range outs {
		}
		return nil
	})
	for _, cli := range early {
		cli := cli
		g.Go(func() error {
			if err := cli.ConnectWithDialer(bufconnDialer(lis)); err != nil {
				return err
			}
			outs, err := cli.Run(runctx, app, compute.NoInput)
			if err != nil {
				return err
			}
			for range outs {
			}
			return nil
		})
	}
	require.NoError(t, g.Wait())

	// the late peer connects after the coordination is done
	require.NoError(t, late.ConnectWithDialer(bufconnDialer(lis)))
	outs, err := late.Run(ctx, app, compute.NoInput)
	require.NoError(t, err)
	_, has := <-outs
	require.False(t, has)

	resCheckCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, cli := range append(early, late) {
		CheckTestSetup(resCheckCtx, t, *app.SetupDescription, cli, lt.RlweParams, lt.SkIdeal, ts.N)
		require.NoError(t, cli.Close())
	}
	helper.Server.GracefulStop()
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

			lt := newLocalTest(t, ts.N, ts.T)

			app := App{
				SetupDescription: &testSetupDescription,
				Circuits:         circuits.TestCircuits,
			}

			helper, lis := lt.newServer(t)
			clients := make([]*HeliumClient, ts.N)
			for i, nid := range lt.peerIDs {
				clients[i] = lt.newClient(t, nid)
			}

			testOuts := make(chan struct {
				sessions.NodeID
				circuits.Output
			}, len(expResult))

			ctx := sessions.NewBackgroundContext(lt.SessParams.ID)
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
				nid := cli.id
				g.Go(func() error {
					err := cli.ConnectWithDialer(bufconnDialer(lis))
					if err != nil {
						return fmt.Errorf("node %s failed to connect: %v", cli.id, err)
					}

					ip := func(ctx context.Context, sess sessions.Session, cd circuits.Descriptor) (chan circuits.Input, error) {
						in := make(chan circuits.Input, 1)
						in <- circuits.Input{OperandLabel: circuits.OperandLabel(fmt.Sprintf("//%s/%s/in", nid, cd.CircuitID)), OperandValue: nodeIDtoTestInput(string(nid))}
						close(in)
						return in, nil
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

			err := g.Wait()
			close(testOuts)
			require.NoError(t, err)

			encoder := bgv.NewEncoder(lt.params)
			for out := range testOuts {
				require.Equal(t, out.NodeID, ts.Reciever)
				pt := &rlwe.Plaintext{Element: out.Ciphertext.Element, Value: out.Ciphertext.Value[0]}
				res := make([]uint64, lt.params.MaxSlots())
				err = encoder.Decode(pt, res)
				require.NoError(t, err)
				exp, has := expResult[out.CircuitID]
				require.True(t, has, "unexpected result for %s", out.CircuitID)
				require.Equal(t, exp, res[0])
				delete(expResult, out.CircuitID)
			}

			require.Empty(t, expResult, "not all expected results were received")

			for _, cli := range clients {
				require.NoError(t, cli.Close())
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
