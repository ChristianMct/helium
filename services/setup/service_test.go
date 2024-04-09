package setup

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ChristianMct/helium/objectstore"
	"github.com/ChristianMct/helium/protocol"
	"github.com/ChristianMct/helium/utils"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/session"

	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
)

var TestPN12QP109 = bgv.ParametersLiteral{ // TODO: could be rlwe but missing lattigo method to convert to rlwe.ParametersLiteral
	LogN:             12,
	Q:                []uint64{0x7ffffffec001, 0x400000008001}, // 47 + 46 bits
	P:                []uint64{0xa001},                         // 15 bits
	PlaintextModulus: 65537,
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

var sd = Description{
	Cpk: true,
	Rlk: true,
	Gks: []uint64{5, 25, 125},
}

var conf = ServiceConfig{
	Protocols: protocol.ExecutorConfig{
		SigQueueSize:     300,
		MaxProtoPerNode:  1,
		MaxAggregation:   1,
		MaxParticipation: 1,
	},
}

type testnode struct {
	*Service
	*session.Session
	//protocol.Coordinator
}

type testNodeTrans struct {
	protocol.Transport
	helperSrv *Service
}

func (tt *testNodeTrans) GetAggregationOutput(ctx context.Context, pd protocol.Descriptor) (*protocol.AggregationOutput, error) {
	return tt.helperSrv.GetAggregationOutput(ctx, pd)
}

func getNodes(t *testing.T, ts testSetting, testSess *session.TestSession) (all, sessNodes map[helium.NodeID]*testnode, helperNode *testnode) {
	hid := helium.NodeID("helper")

	sessParams := testSess.SessParams

	nids := utils.NewSet(sessParams.Nodes)

	protoTrans := protocol.NewTestTransport()

	all = make(map[helium.NodeID]*testnode, ts.N+1)
	clou := new(testnode)
	all["helper"] = clou

	srvTrans := &testNodeTrans{Transport: protoTrans}
	os := objectstore.NewMemObjectStore()
	var err error
	clou.Service, err = NewSetupService(hid, testSess.HelperSession, conf, srvTrans, os)
	if err != nil {
		t.Fatal(err)
	}
	//clou.Coordinator = coord

	clients := make(map[helium.NodeID]*testnode, ts.N)
	for nid := range nids {
		cli := &testnode{}
		cli.Session = testSess.NodeSessions[nid]
		srvTrans := &testNodeTrans{Transport: protoTrans.TransportFor(nid), helperSrv: clou.Service}
		cli.Service, err = NewSetupService(nid, testSess.NodeSessions[nid], conf, srvTrans, objectstore.NewNullObjectStore())
		if err != nil {
			t.Fatal(err)
		}
		//cli.Coordinator = coord.Register(nid)
		clients[nid] = cli
		all[nid] = cli
	}
	return all, clients, clou
}

// TestSetup tests the setup service in cloud-assisted mode with one helper and N peer nodes.
func TestSetup(t *testing.T) {
	for _, literalParams := range rangeParam {
		for _, ts := range testSettings {
			if ts.T == 0 {
				ts.T = ts.N // N-out-of-N scenario
			}

			t.Run(fmt.Sprintf("NParty=%d/T=%d/logN=%d", ts.N, ts.T, literalParams.LogN), func(t *testing.T) {
				hid := helium.NodeID("helper")

				testSess, err := session.NewTestSession(ts.N, ts.T, literalParams, hid)
				if err != nil {
					t.Fatal(err)
				}

				all, _, clou := getNodes(t, ts, testSess)
				coord := protocol.NewTestCoordinator(hid)

				ctx := helium.NewBackgroundContext(testSess.SessParams.ID)
				// runs the setup
				go func() {
					sigList := DescriptionToSignatureList(sd)
					for _, sig := range sigList {
						clou.RunSignature(ctx, sig)
					}
					coord.Close()
				}()

				// run all the nodes
				g, ctx := errgroup.WithContext(ctx)
				for nid, node := range all {
					nid := nid
					node := node
					g.Go(func() error {
						clou.Service.Register(nid)
						err := node.Run(ctx, coord.Register(nid))
						return errors.WithMessagef(err, "error at node %s", nid)
					})
				}
				err = g.Wait()
				require.Nil(t, err)

				for _, n := range all {
					CheckTestSetup(ctx, t, n.self, testSess, sd, n)
				}
			})
		}
	}
}

// TestSetupLateConnect tests the case of N-T nodes connecting after the setup has completed.
func TestSetupLateConnect(t *testing.T) {
	for _, literalParams := range rangeParam {
		for _, ts := range testSettings {
			if ts.T == 0 {
				ts.T = ts.N // N-out-of-N scenario
			}

			t.Run(fmt.Sprintf("NParty=%d/T=%d/logN=%d", ts.N, ts.T, literalParams.LogN), func(t *testing.T) {
				hid := helium.NodeID("helper")

				testSess, err := session.NewTestSession(ts.N, ts.T, literalParams, hid)
				if err != nil {
					t.Fatal(err)
				}

				all, cli, clou := getNodes(t, ts, testSess)
				clis := make([]*testnode, 0, ts.N)
				for _, node := range cli {
					clis = append(clis, node)
				}
				coord := protocol.NewTestCoordinator(hid)

				ctx := helium.NewBackgroundContext(testSess.SessParams.ID)
				// runs the setup
				go func() {
					sigList := DescriptionToSignatureList(sd)
					for _, sig := range sigList {
						clou.RunSignature(ctx, sig)
					}
					coord.Close()
				}()

				// run helper and t session nodes
				g, ctx := errgroup.WithContext(ctx)
				g.Go(func() error {
					err := clou.Run(ctx, coord)
					return errors.WithMessagef(err, "error at node %s", hid)
				})
				for _, node := range clis[:ts.T] {
					nid := node.self
					node := node
					g.Go(func() error {
						clou.Service.Register(nid)
						err := node.Run(ctx, coord.Register(nid))
						return errors.WithMessagef(err, "error at node %s", nid)
					})
				}
				err = g.Wait()
				require.Nil(t, err)

				// run the remaining nodes
				for _, node := range clis[ts.T:] {
					err := node.Run(ctx, coord.Register(node.self))
					require.Nil(t, err)
				}

				for _, n := range all {
					CheckTestSetup(ctx, t, n.self, testSess, sd, n)
				}
			})
		}
	}
}

func TestSetupRetries(t *testing.T) {

	t.Skip("not yet implemented")

	ts := testSetting{N: 3, T: 2}
	literalParams := TestPN12QP109

	hid := helium.NodeID("helper")

	testSess, err := session.NewTestSession(ts.N, ts.T, literalParams, hid)
	if err != nil {
		t.Fatal(err)
	}

	all, cli, clou := getNodes(t, ts, testSess)
	clis := make([]*testnode, 0, ts.N)
	for _, node := range cli {
		clis = append(clis, node)
	}
	coord := protocol.NewTestCoordinator(hid)

	ctx := helium.NewBackgroundContext(testSess.SessParams.ID)

	// runs the setup
	go func() {
		// sigList := DescriptionToSignatureList(sd)
		// for _, sig := range sigList {
		// 	clou.RunSignature(ctx, sig)
		// }
		err = clou.RunSignature(ctx, protocol.Signature{Type: protocol.CKG})
		require.Nil(t, err)
		coord.Close()
	}()

	// runs helper
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		err := clou.Run(ctx, coord)
		return errors.WithMessagef(err, "error at node %s", hid)
	})

	// register p0, p1
	for _, cli := range clis[:2] {
		clou.Service.Register(cli.self)
	}

	// runs only p0
	g.Go(func() error {
		err := clis[0].Run(ctx, coord.Register(clis[0].self))
		return errors.WithMessagef(err, "error at node %s", clis[0].self)
	})

	<-time.After(time.Second) // leaves some time for the helper to start the failing protocol

	// unregisters p1
	err = clou.Service.Unregister(clis[1].self)
	require.Nil(t, err)

	// registers and run p2
	g.Go(func() error {
		clou.Register(clis[2].self)
		err := clis[2].Run(ctx, coord.Register(clis[2].self))
		return errors.WithMessagef(err, "error at node %s", clis[2].self)
	})
	err = g.Wait()
	require.Nil(t, err)

	// run p1
	err = clis[1].Run(ctx, coord.Register(clis[1].self))
	require.Nil(t, err)

	for _, n := range all {
		CheckTestSetup(ctx, t, n.self, testSess, Description{Cpk: true}, n)
	}
}
