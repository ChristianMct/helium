package setup

import (
	"fmt"
	"log"
	"testing"

	"github.com/ChristianMct/helium/coordinator"
	"github.com/ChristianMct/helium/objectstore"
	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/utils"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/ChristianMct/helium/sessions"

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
	Protocols: protocols.ExecutorConfig{
		SigQueueSize:     300,
		MaxProtoPerNode:  1,
		MaxAggregation:   1,
		MaxParticipation: 1,
	},
}

type testnode struct {
	*Service
	*sessions.Session
	//protocol.Coordinator
}

func getNodes(t *testing.T, ts testSetting, testSess *sessions.TestSession) (all, sessNodes map[sessions.NodeID]*testnode, helperNode *testnode) {
	hid := sessions.NodeID("helper")

	sessParams := testSess.SessParams

	nids := utils.NewSet(sessParams.Nodes)

	//protoTrans := protocol.NewTestTransport()

	all = make(map[sessions.NodeID]*testnode, ts.N+1)
	clou := new(testnode)
	all["helper"] = clou

	os := objectstore.NewMemObjectStore()
	var err error
	clou.Service, err = NewSetupService(hid, testSess.HelperSession, conf, os)
	if err != nil {
		t.Fatal(err)
	}

	clients := make(map[sessions.NodeID]*testnode, ts.N)
	for nid := range nids {
		cli := &testnode{}
		cli.Session = testSess.NodeSessions[nid]
		cli.Service, err = NewSetupService(nid, testSess.NodeSessions[nid], conf, objectstore.NewNullObjectStore())
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
				hid := sessions.NodeID("helper")

				testSess, err := sessions.NewTestSession(ts.N, ts.T, literalParams, hid)
				if err != nil {
					t.Fatal(err)
				}

				all, _, clou := getNodes(t, ts, testSess)
				tc := coordinator.NewTestCoordinator[Event](hid)
				tt := newTestTransport(clou.Service)

				ctx := sessions.NewBackgroundContext(testSess.SessParams.ID)
				// runs the setup
				go func() {
					sigList := DescriptionToSignatureList(sd)
					for _, sig := range sigList {
						clou.RunSignature(ctx, sig)
					}
					tc.Close()
				}()

				// run all the nodes
				g, nodesRunCtx := errgroup.WithContext(ctx)
				for nid, node := range all {
					nid := nid
					node := node
					g.Go(func() error {
						if nid != hid {
							clou.Service.Register(nid)
						}
						err := node.Run(nodesRunCtx, tc, tt.TransportFor(nid), sd)
						return errors.WithMessagef(err, "error at node %s", nid)
					})
				}
				err = g.Wait()
				require.Nil(t, err)

				for _, n := range all {
					CheckTestSetup(ctx, t, sd, n, testSess.RlweParams, testSess.SkIdeal, ts.N)
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
				hid := sessions.NodeID("helper")

				testSess, err := sessions.NewTestSession(ts.N, ts.T, literalParams, hid)
				if err != nil {
					t.Fatal(err)
				}

				all, cli, clou := getNodes(t, ts, testSess)
				clis := make([]*testnode, 0, ts.N)
				for _, node := range cli {
					clis = append(clis, node)
				}
				tc := coordinator.NewTestCoordinator[Event](hid)
				tt := newTestTransport(clou.Service)

				ctx := sessions.NewBackgroundContext(testSess.SessParams.ID)
				// runs the setup
				go func() {
					sigList := DescriptionToSignatureList(sd)
					for _, sig := range sigList {
						clou.RunSignature(ctx, sig)
					}
					tc.Close()
				}()

				// run helper and t session nodes
				g, nodesRunCtx := errgroup.WithContext(ctx)
				g.Go(func() error {
					err := clou.Run(nodesRunCtx, tc, tt.TransportFor(hid), sd)
					return errors.WithMessagef(err, "error at node %s", hid)
				})
				for _, node := range clis[:ts.T] {
					nid := node.self
					node := node
					g.Go(func() error {
						clou.Service.Register(nid)
						err := node.Run(nodesRunCtx, tc, tt.TransportFor(nid), sd)
						return errors.WithMessagef(err, "error at node %s", nid)
					})
				}
				err = g.Wait()
				require.Nil(t, err)

				// run the remaining nodes
				for _, node := range clis[ts.T:] {
					err := node.Run(ctx, tc, tt.TransportFor(node.self), sd)
					require.Nil(t, err)
				}

				for _, n := range all {
					CheckTestSetup(ctx, t, sd, n, testSess.RlweParams, testSess.SkIdeal, ts.N)
				}
			})
		}
	}
}

func TestSetupRetries(t *testing.T) {

	ts := testSetting{N: 3, T: 2}
	literalParams := TestPN12QP109

	hid := sessions.NodeID("helper")

	testSess, err := sessions.NewTestSession(ts.N, ts.T, literalParams, hid)
	if err != nil {
		t.Fatal(err)
	}

	all, cli, clou := getNodes(t, ts, testSess)
	tc := coordinator.NewTestCoordinator[Event](hid)
	tt := newTestTransport(clou.Service)

	ctx := sessions.NewBackgroundContext(testSess.SessParams.ID)

	sd := Description{Cpk: true}

	// runs the setup
	go func() {
		err = clou.RunSignature(ctx, protocols.Signature{Type: protocols.CKG})
		require.Nil(t, err)
		tc.Close()
	}()

	// runs helper
	g, nodesRunCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		err := clou.Run(nodesRunCtx, tc, tt, sd)
		return errors.WithMessagef(err, "error at node %s", hid)
	})

	p0, p1, p2 := cli["node-0"], cli["node-1"], cli["node-2"]

	// register p0, p1
	clou.Service.Register(p0.self)
	clou.Service.Register(p1.self)

	// runs only p0
	g.Go(func() error {
		err := p0.Run(nodesRunCtx, tc, tt.TransportFor(p0.self), sd)
		return errors.WithMessagef(err, "error at node %s", p0.self)
	})

	p1Chan, _, err := tc.Register(sessions.ContextWithNodeID(nodesRunCtx, p1.self))
	require.Nil(t, err)
	ev := <-p1Chan.Incoming
	require.Equal(t,
		Event{
			Event: protocols.Event{
				EventType: protocols.Started,
				Descriptor: protocols.Descriptor{
					Signature:    protocols.Signature{Type: protocols.CKG},
					Participants: []sessions.NodeID{"node-0", "node-1"},
					Aggregator:   "helper",
				},
			},
		},
		ev)

	// unregisters p1
	err = clou.Service.Unregister(p1.self)
	require.Nil(t, err)

	ev = <-p1Chan.Incoming
	require.Equal(t,
		Event{
			protocols.Event{
				EventType: protocols.Failed,
				Descriptor: protocols.Descriptor{
					Signature:    protocols.Signature{Type: protocols.CKG},
					Participants: []sessions.NodeID{"node-0", "node-1"},
					Aggregator:   "helper",
				},
			},
		},
		ev)

	// registers and run p2
	g.Go(func() error {
		clou.Register(p2.self)
		err := p2.Run(nodesRunCtx, tc, tt.TransportFor(p2.self), sd)
		return errors.WithMessagef(err, "error at node %s", p2.self)
	})
	ev = <-p1Chan.Incoming
	require.Equal(t,
		Event{
			protocols.Event{
				EventType: protocols.Started,
				Descriptor: protocols.Descriptor{
					Signature:    protocols.Signature{Type: protocols.CKG},
					Participants: []sessions.NodeID{"node-0", "node-2"},
					Aggregator:   "helper",
				},
			},
		},
		ev)
	log.Println("[test] got started on p1")

	ev = <-p1Chan.Incoming
	require.Equal(t,
		Event{
			protocols.Event{
				EventType: protocols.Completed,
				Descriptor: protocols.Descriptor{
					Signature:    protocols.Signature{Type: protocols.CKG},
					Participants: []sessions.NodeID{"node-0", "node-2"},
					Aggregator:   "helper",
				},
			},
		},
		ev)
	err = g.Wait()
	require.Nil(t, err)

	// run p1
	err = p1.Run(ctx, tc, tt.TransportFor(p1.self), sd)
	require.Nil(t, err)

	for _, n := range all {
		CheckTestSetup(ctx, t, Description{Cpk: true}, n, testSess.RlweParams, testSess.SkIdeal, ts.N)
	}
}
