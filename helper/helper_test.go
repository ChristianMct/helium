package helper

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/heliumtest"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v5/mhe"
	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/test/bufconn"
)

type TestCircuitSig struct {
	helium.Signature
	ExpResult uint64
}

var testSessionParameters = helium.Parameters{
	ID:            "test-session",
	FHEParameters: bgv.ParametersLiteral{LogN: 12, LogQ: []int{45, 45}, LogP: []int{19}, PlaintextModulus: 79873},
	// Threshold:     set by test
}

type testSetting struct {
	N           int // N - total parties
	T           int // T - parties in the access structure
	CircuitSigs []TestCircuitSig
	Reciever    helium.NodeID
	Rep         int // numer of repetition for each circuit
}

var testSetupDescription = helium.SetupDescription{
	Cpk: true,
	Rlk: true,
	Gks: []uint64{5, 25, 125},
}

var testCircuits2P = []TestCircuitSig{
	{Signature: helium.Signature{Name: "bgv-add-2", Args: nil}, ExpResult: 1},
	{Signature: helium.Signature{Name: "bgv-mul-2", Args: nil}, ExpResult: 0},
	{Signature: helium.Signature{Name: "bgv-add-n", Args: map[string]string{"n": "2"}}, ExpResult: 1},
}

var testCircuits3P = []TestCircuitSig{
	{Signature: helium.Signature{Name: "bgv-add-2", Args: nil}, ExpResult: 1},
	{Signature: helium.Signature{Name: "bgv-mul-2", Args: nil}, ExpResult: 0},
	{Signature: helium.Signature{Name: "bgv-add-n", Args: map[string]string{"n": "2"}}, ExpResult: 1},
	{Signature: helium.Signature{Name: "bgv-add-n", Args: map[string]string{"n": "3"}}, ExpResult: 3},
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
	testSmudging      = 40.0
)

var testNodeMapping = map[string]helium.NodeID{"p1": "peer-0", "p2": "peer-1", "p3": "peer-2", "eval": "helper"}

// localTest is a helper + N peers test setting.
type localTest struct {
	*heliumtest.Sessions
	params   bgv.Parameters
	helperID helium.NodeID
	peerIDs  []helium.NodeID
	nl       helium.NodeList
	configs  map[helium.NodeID]Config
	secrets  map[helium.NodeID]*helium.Secrets
}

func newLocalTest(t *testing.T, N, T int) *localTest {
	lt := &localTest{helperID: "helper", configs: make(map[helium.NodeID]Config)}

	sp := testSessionParameters
	sp.Threshold = T
	sp.PublicSeed = []byte{'l', 'a', 't', 't', 'i', 'g', '0'}
	sp.ShamirPks = make(map[helium.NodeID]mhe.ShamirPublicPoint, N)
	lt.nl = helium.NodeList{{NodeID: lt.helperID, NodeAddress: "local"}}
	for i := 0; i < N; i++ {
		nid := helium.NodeID("peer-" + strconv.Itoa(i))
		lt.peerIDs = append(lt.peerIDs, nid)
		sp.Nodes = append(sp.Nodes, nid)
		sp.ShamirPks[nid] = mhe.ShamirPublicPoint(i + 1)
		lt.nl = append(lt.nl, helium.NodeInfo{NodeID: nid})
	}

	var err error
	lt.Sessions, err = heliumtest.NewSessionsFromParams(sp, lt.helperID)
	require.NoError(t, err)
	lt.secrets, err = heliumtest.GenSecretKeys(sp)
	require.NoError(t, err)

	var ok bool
	lt.params, ok = lt.FHEParameters.(bgv.Parameters)
	require.True(t, ok)

	objStore := helium.ObjectStoreConfig{BackendName: "mem"}
	lt.configs[lt.helperID] = Config{
		Config: helium.Config{
			ID:                lt.helperID,
			SessionParameters: sp,
			MaxEvaluation:     4,
			ObjectStore:       objStore,
		},
		Helper:          helium.NodeInfo{NodeID: lt.helperID, NodeAddress: "local"},
		MaxProtoPerNode: 1,
		TLS:             TLSConfig{InsecureChannels: true},
	}
	for _, nid := range lt.peerIDs {
		lt.configs[nid] = Config{
			Config: helium.Config{
				ID:                nid,
				SessionParameters: sp,
				MaxParticipation:  1,
				MaxEvaluation:     1,
				ObjectStore:       objStore,
			},
			Helper: helium.NodeInfo{NodeID: lt.helperID, NodeAddress: "local"},
			TLS:    TLSConfig{InsecureChannels: true},
		}
	}
	return lt
}

func (lt *localTest) secretProvider(sid helium.SessionID, nid helium.NodeID) (*helium.Secrets, error) {
	if sid != lt.SessParams.ID {
		return nil, fmt.Errorf("unknown session %s", sid)
	}
	sec, has := lt.secrets[nid]
	if !has {
		return nil, fmt.Errorf("no secrets for node %s", nid)
	}
	return sec, nil
}

func (lt *localTest) newServer(t *testing.T) (*Server, *bufconn.Listener) {
	hsv, err := NewServer(lt.configs[lt.helperID])
	require.NoError(t, err)
	lis := bufconn.Listen(buffConBufferSize)
	go func() {
		if err := hsv.Serve(lis); err != nil {
			log.Printf("server error: %s", err)
		}
	}()
	return hsv, lis
}

func (lt *localTest) newClient(t *testing.T, nid helium.NodeID) *Client {
	cli, err := NewClient(lt.configs[nid], lt.secretProvider)
	require.NoError(t, err)
	return cli
}

// newConnectedClients creates and connects the clients of all the peers.
func (lt *localTest) newConnectedClients(t *testing.T, lis *bufconn.Listener, nids ...helium.NodeID) map[helium.NodeID]*Client {
	clients := make(map[helium.NodeID]*Client, len(nids))
	for _, nid := range nids {
		cli := lt.newClient(t, nid)
		require.NoError(t, cli.ConnectWithDialer(bufconnDialer(lis)))
		clients[nid] = cli
	}
	return clients
}

// runAll runs the app on the helper and the clients, and waits for all of them to return.
func runAll(ctx context.Context, app helium.App, hsv *Server, clients map[helium.NodeID]*Client) error {
	g := new(errgroup.Group)
	g.Go(func() error { return hsv.Run(ctx, app) })
	for _, cli := range clients {
		cli := cli
		g.Go(func() error { return cli.Run(ctx, app) })
	}
	return g.Wait()
}

func bufconnDialer(lis *bufconn.Listener) Dialer {
	return func(context.Context, string) (net.Conn, error) { return lis.Dial() }
}

func testContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(cancel)
	return ctx
}

// testInputs returns the test inputs of node nid (nil for the helper, which has no input).
func testInputs(nid, helperID helium.NodeID) map[string]any {
	if nid == helperID {
		return nil
	}
	return map[string]any{"in": nodeIDtoTestInput(string(nid))}
}

// testResults collects the decrypted results of the test apps, by circuit id.
type testResults struct {
	mu      sync.Mutex
	results map[helium.CircuitID]uint64
}

func (tr *testResults) set(cid helium.CircuitID, v uint64) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if tr.results == nil {
		tr.results = make(map[helium.CircuitID]uint64)
	}
	tr.results[cid] = v
}

// evaluateAndDecrypt is the test app logic for one circuit: it evaluates the circuit, decrypts
// its output to the receiver, and records the result at the receiver.
func (lt *localTest) evaluateAndDecrypt(ctx context.Context, rt helium.Runtime, cd helium.Descriptor, receiver helium.NodeID, res *testResults) error {
	outs, err := rt.Evaluate(ctx, cd, testInputs(rt.ID(), lt.helperID))
	if err != nil {
		return fmt.Errorf("circuit %s: %w", cd.HID(), err)
	}
	pt, err := rt.Decrypt(ctx, outs["out"], receiver, testSmudging)
	if err != nil {
		return fmt.Errorf("decryption of %s: %w", outs["out"].ID, err)
	}
	if rt.ID() != receiver {
		if pt != nil {
			return fmt.Errorf("non-receiver %s got a plaintext", rt.ID())
		}
		return nil
	}
	if pt == nil {
		return fmt.Errorf("receiver %s got no plaintext", rt.ID())
	}
	v := make([]uint64, lt.params.MaxSlots())
	if err := bgv.NewEncoder(lt.params).Decode(pt, v); err != nil {
		return err
	}
	res.set(cd.CircuitID, v[0])
	return nil
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
			ctx := testContext(t)

			app := helium.App{
				Setup: &testSetupDescription,
			}

			hsv, lis := lt.newServer(t)
			clients := lt.newConnectedClients(t, lis, lt.peerIDs...)
			require.NoError(t, runAll(ctx, app, hsv, clients))

			heliumtest.CheckSetup(ctx, t, *app.Setup, hsv, lt.RlweParams, lt.SkIdeal, ts.N)

			for _, cli := range clients {
				log.Println("checking setup for", cli.id)
				resCheckCtx, runCheckCancel := context.WithTimeout(ctx, time.Second)
				heliumtest.CheckSetup(resCheckCtx, t, *app.Setup, cli, lt.RlweParams, lt.SkIdeal, ts.N)
				runCheckCancel()

				require.NoError(t, cli.Close())
			}

			hsv.Server.GracefulStop()
		})
	}
}

// TestLateJoiner checks that a peer connecting after the helper has terminated the
// coordination catches up from the event log: it obtains the setup keys, and its Main
// runs through the completed circuit and protocol.
func TestLateJoiner(t *testing.T) {
	ts := testSetting{N: 3, T: 2}
	lt := newLocalTest(t, ts.N, ts.T)
	ctx := testContext(t)

	cd := helium.Descriptor{
		Signature:   helium.Signature{Name: "bgv-add-2"},
		CircuitID:   "add-0",
		NodeMapping: testNodeMapping,
		Evaluator:   lt.helperID,
	}
	res := new(testResults)
	app := helium.App{
		Setup:    &testSetupDescription,
		Circuits: heliumtest.Circuits,
		Main: func(ctx context.Context, rt helium.Runtime) error {
			return lt.evaluateAndDecrypt(ctx, rt, cd, lt.helperID, res)
		},
	}

	hsv, lis := lt.newServer(t)
	early := lt.newConnectedClients(t, lis, lt.peerIDs[0], lt.peerIDs[1])
	require.NoError(t, runAll(ctx, app, hsv, early))
	require.Equal(t, uint64(1), res.results[cd.CircuitID])

	// the late peer connects after the coordination is done
	late := lt.newConnectedClients(t, lis, lt.peerIDs[2])[lt.peerIDs[2]]
	require.NoError(t, late.Run(ctx, app))
	require.True(t, late.Circuits().IsCompleted(cd.CircuitID))

	resCheckCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, cli := range []*Client{early[lt.peerIDs[0]], early[lt.peerIDs[1]], late} {
		heliumtest.CheckSetup(resCheckCtx, t, *app.Setup, cli, lt.RlweParams, lt.SkIdeal, ts.N)
		require.NoError(t, cli.Close())
	}
	hsv.Server.GracefulStop()
}

// TestCompute runs an app evaluating the test circuits and decrypting their outputs to the
// receiver: all nodes run the same Main, which evaluates the circuits concurrently.
func TestCompute(t *testing.T) {
	for _, ts := range testSettings {
		if ts.T == 0 {
			ts.T = ts.N
		}
		if ts.Rep == 0 {
			ts.Rep = 1
		}

		t.Run(fmt.Sprintf("NParty=%d/T=%d/rec=%s/rep=%d", ts.N, ts.T, ts.Reciever, ts.Rep), func(t *testing.T) {

			lt := newLocalTest(t, ts.N, ts.T)
			ctx := testContext(t)

			// the circuit evaluations
			type evaluation struct {
				cd  helium.Descriptor
				exp uint64
			}
			evals := make([]evaluation, 0, len(ts.CircuitSigs)*ts.Rep)
			for i, tc := range ts.CircuitSigs {
				for rep := 0; rep < ts.Rep; rep++ {
					cid := helium.CircuitID(fmt.Sprintf("%s-%d-%d", tc.Name, i, rep))
					cd := helium.Descriptor{Signature: tc.Signature, CircuitID: cid, NodeMapping: testNodeMapping, Evaluator: lt.helperID}
					evals = append(evals, evaluation{cd: cd, exp: tc.ExpResult})
				}
			}

			res := new(testResults)
			app := helium.App{
				Setup:    &testSetupDescription,
				Circuits: heliumtest.Circuits,
				Main: func(ctx context.Context, rt helium.Runtime) error {
					g, gctx := errgroup.WithContext(ctx)
					for _, ev := range evals {
						ev := ev
						g.Go(func() error { return lt.evaluateAndDecrypt(gctx, rt, ev.cd, ts.Reciever, res) })
					}
					return g.Wait()
				},
			}

			hsv, lis := lt.newServer(t)
			clients := lt.newConnectedClients(t, lis, lt.peerIDs...)
			require.NoError(t, runAll(ctx, app, hsv, clients))

			for _, ev := range evals {
				v, has := res.results[ev.cd.CircuitID]
				require.True(t, has, "no result for circuit %s", ev.cd.HID())
				require.Equal(t, ev.exp, v, "circuit %s", ev.cd.HID())
			}

			for _, cli := range clients {
				require.NoError(t, cli.Close())
			}
			hsv.Server.GracefulStop()
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
