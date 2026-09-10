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
	"github.com/ChristianMct/helium/sessions"
	"github.com/stretchr/testify/require"
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
	{Signature: circuits.Signature{Name: "bgv-add-2", Args: nil}, ExpResult: 1},
	{Signature: circuits.Signature{Name: "bgv-mul-2", Args: nil}, ExpResult: 0},
	{Signature: circuits.Signature{Name: "bgv-add-n", Args: map[string]string{"n": "2"}}, ExpResult: 1},
}

var testCircuits3P = []TestCircuitSig{
	{Signature: circuits.Signature{Name: "bgv-add-2", Args: nil}, ExpResult: 1},
	{Signature: circuits.Signature{Name: "bgv-mul-2", Args: nil}, ExpResult: 0},
	{Signature: circuits.Signature{Name: "bgv-add-n", Args: map[string]string{"n": "2"}}, ExpResult: 1},
	{Signature: circuits.Signature{Name: "bgv-add-n", Args: map[string]string{"n": "3"}}, ExpResult: 3},
}

var testSettings = []testSetting{
	{N: 2, CircuitSigs: testCircuits2P, Reciever: "peer-0"},
	{N: 2, CircuitSigs: testCircuits2P, Reciever: "helper"},
	{N: 3, T: 2, CircuitSigs: testCircuits3P, Reciever: "peer-0"},
	{N: 3, T: 2, CircuitSigs: testCircuits3P, Reciever: "helper"},
	{N: 3, T: 2, CircuitSigs: testCircuits3P, Reciever: "helper", Rep: 10},
}

const (
	buffConBufferSize = 65 * 1024 * 1024
	testTimeout       = 3 * time.Minute
)

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
		CircuitsConfig:    circuits.Config{MaxEvaluation: 4},
		ObjectStoreConfig: objStore,
		TLSConfig:         TLSConfig{InsecureChannels: true},
	}
	for _, nid := range lt.peerIDs {
		lt.configs[nid] = Config{
			ID:                nid,
			HelperID:          lt.helperID,
			SessionParameters: []sessions.Parameters{sp},
			ProtocolsConfig:   protocols.Config{MaxParticipation: 1},
			CircuitsConfig:    circuits.Config{MaxEvaluation: 1},
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

func testContext(t *testing.T, sessID sessions.ID) context.Context {
	ctx, cancel := context.WithTimeout(sessions.NewBackgroundContext(sessID), testTimeout)
	t.Cleanup(cancel)
	return ctx
}

// testInputProvider provides the test input of node nid for all its input operands.
func testInputProvider(nid sessions.NodeID) circuits.InputProvider {
	return func(ctx context.Context, cd circuits.Descriptor, ids []circuits.OperandID) (<-chan circuits.Input, error) {
		in := make(chan circuits.Input, len(ids))
		for _, id := range ids {
			in <- circuits.Input{ID: id, Value: nodeIDtoTestInput(string(nid))}
		}
		close(in)
		return in, nil
	}
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
			ctx := testContext(t, lt.SessParams.ID)

			app := App{
				SetupDescription: &testSetupDescription,
			}

			helper, lis := lt.newServer(t)
			require.NoError(t, helper.Run(ctx, app, circuits.NoInput))

			clients := make([]*HeliumClient, ts.N)
			for i, nid := range lt.peerIDs {
				clients[i] = lt.newClient(t, nid)
				require.NoError(t, clients[i].ConnectWithDialer(bufconnDialer(lis)))
				require.NoError(t, clients[i].Run(ctx, app, circuits.NoInput))
			}

			require.NoError(t, helper.Close(ctx))
			helper.Wait()
			for _, cli := range clients {
				cli.Wait()
			}

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
	ctx := testContext(t, lt.SessParams.ID)
	app := App{SetupDescription: &testSetupDescription}

	helper, lis := lt.newServer(t)
	require.NoError(t, helper.Run(ctx, app, circuits.NoInput))

	early := []*HeliumClient{lt.newClient(t, lt.peerIDs[0]), lt.newClient(t, lt.peerIDs[1])}
	late := lt.newClient(t, lt.peerIDs[2])
	for _, cli := range early {
		require.NoError(t, cli.ConnectWithDialer(bufconnDialer(lis)))
		require.NoError(t, cli.Run(ctx, app, circuits.NoInput))
	}
	require.NoError(t, helper.Close(ctx))
	helper.Wait()
	for _, cli := range early {
		cli.Wait()
	}

	// the late peer connects after the coordination is done
	require.NoError(t, late.ConnectWithDialer(bufconnDialer(lis)))
	require.NoError(t, late.Run(ctx, app, circuits.NoInput))
	late.Wait()

	resCheckCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, cli := range append(early, late) {
		CheckTestSetup(resCheckCtx, t, *app.SetupDescription, cli, lt.RlweParams, lt.SkIdeal, ts.N)
		require.NoError(t, cli.Close())
	}
	helper.Server.GracefulStop()
}

// TestCompute evaluates the test circuits and decrypts their outputs to the receiver.
// The test acts as the application: it requests the circuit evaluations, then the
// decryption protocols on their outputs.
func TestCompute(t *testing.T) {
	for _, ts := range testSettings {
		if ts.T == 0 {
			ts.T = ts.N
		}
		if ts.Rep == 0 {
			ts.Rep = 1
		}

		nodemap := map[string]sessions.NodeID{"p1": "peer-0", "p2": "peer-1", "p3": "peer-2", "eval": "helper"}

		t.Run(fmt.Sprintf("NParty=%d/T=%d/rec=%s/rep=%d", ts.N, ts.T, ts.Reciever, ts.Rep), func(t *testing.T) {

			lt := newLocalTest(t, ts.N, ts.T)
			ctx := testContext(t, lt.SessParams.ID)

			app := App{
				SetupDescription: &testSetupDescription,
				Circuits:         circuits.TestCircuits,
			}

			// the circuit evaluations and the decryption of their outputs
			type evaluation struct {
				cd     circuits.Descriptor
				decSig protocols.Signature
				exp    uint64
			}
			evals := make([]evaluation, 0, len(ts.CircuitSigs)*ts.Rep)
			for i, tc := range ts.CircuitSigs {
				for rep := 0; rep < ts.Rep; rep++ {
					cid := sessions.CircuitID(fmt.Sprintf("%s-%d-%d", tc.Name, i, rep))
					cd := circuits.Descriptor{Signature: tc.Signature, CircuitID: cid, NodeMapping: nodemap, Evaluator: lt.helperID}
					outID := circuits.NewOperandID(lt.helperID, cid, "out")
					decSig := protocols.Signature{Type: protocols.DEC, Args: map[string]string{
						"op": string(outID), "target": string(ts.Reciever), "smudging": "40.0",
					}}
					evals = append(evals, evaluation{cd: cd, decSig: decSig, exp: tc.ExpResult})
				}
			}

			helper, lis := lt.newServer(t)
			require.NoError(t, helper.Run(ctx, app, circuits.NoInput))

			clients := make(map[sessions.NodeID]*HeliumClient, ts.N)
			for _, nid := range lt.peerIDs {
				cli := lt.newClient(t, nid)
				require.NoError(t, cli.ConnectWithDialer(bufconnDialer(lis)))
				require.NoError(t, cli.Run(ctx, app, testInputProvider(nid)))
				clients[nid] = cli
			}

			// the application: evaluates the circuits, then decrypts their outputs to the receiver
			var receiver *protocols.MHEMPC
			if ts.Reciever == lt.helperID {
				receiver = helper.Protocols()
			} else {
				receiver = clients[ts.Reciever].Protocols()
			}

			g, gctx := errgroup.WithContext(ctx)
			for _, ev := range evals {
				require.NoError(t, helper.Evaluate(ctx, ev.cd))
			}
			for _, ev := range evals {
				ev := ev
				g.Go(func() error {
					if _, err := helper.Circuits().AwaitCompleted(gctx, ev.cd.CircuitID); err != nil {
						return fmt.Errorf("circuit %s: %w", ev.cd.HID(), err)
					}
					return helper.RunSignature(gctx, ev.decSig)
				})
			}
			require.NoError(t, g.Wait())

			encoder := bgv.NewEncoder(lt.params)
			for _, ev := range evals {
				pd, err := receiver.AwaitCompleted(ctx, ev.decSig)
				require.NoError(t, err)
				pt, err := receiver.DecryptOutput(ctx, pd)
				require.NoError(t, err)
				res := make([]uint64, lt.params.MaxSlots())
				require.NoError(t, encoder.Decode(pt, res))
				require.Equal(t, ev.exp, res[0], "circuit %s", ev.cd.HID())
			}

			// a non-receiver cannot decrypt
			for nid, cli := range clients {
				if nid == ts.Reciever {
					continue
				}
				pd, err := cli.Protocols().AwaitCompleted(ctx, evals[0].decSig)
				require.NoError(t, err)
				_, err = cli.Protocols().DecryptOutput(ctx, pd)
				require.Error(t, err)
				break
			}

			require.NoError(t, helper.Close(ctx))
			helper.Wait()
			for _, cli := range clients {
				cli.Wait()
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
