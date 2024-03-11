package setup

import (
	"context"
	"fmt"
	"testing"

	"github.com/ldsec/helium/pkg/protocols"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/ldsec/helium/pkg/pkg"

	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v4/bgv"
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
	protocols.Coordinator
}

type testNodeTrans struct {
	protocols.Transport
	helperSrv *Service
}

func (tt *testNodeTrans) GetAggregationOutput(ctx context.Context, pd protocols.Descriptor) (*protocols.AggregationOutput, error) {
	return tt.helperSrv.GetAggregationOutput(ctx, pd)
}

// TestCloudAssistedSetup tests the setup service in cloud-assisted mode with one helper and N peer nodes.
func TestCloudAssistedSetup(t *testing.T) {
	for _, literalParams := range rangeParam {
		for _, ts := range testSettings {
			if ts.T == 0 {
				ts.T = ts.N // N-out-of-N scenario
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

				coord := protocols.NewTestCoordinator()
				protoTrans := protocols.NewTestTransport()

				all := make(map[pkg.NodeID]*testnode, ts.N+1)
				clou := new(testnode)
				all["helper"] = clou

				conf := ServiceConfig{
					Protocols: protocols.ExecutorConfig{
						SigQueueSize:     300,
						MaxProtoPerNode:  1,
						MaxAggregation:   1,
						MaxParticipation: 1,
					},
				}

				srvTrans := &testNodeTrans{Transport: protoTrans}
				clou.Service, err = NewSetupService(hid, testSess.HelperSession, conf, srvTrans, testSess.HelperSession.ObjectStore)
				if err != nil {
					t.Fatal(err)
				}
				clou.Coordinator = coord

				clients := make(map[pkg.NodeID]*testnode, ts.N)
				for nid := range nids {
					cli := &testnode{}
					cli.Session = testSess.NodeSessions[nid]
					srvTrans := &testNodeTrans{Transport: protoTrans.TransportFor(nid), helperSrv: clou.Service}
					cli.Service, err = NewSetupService(nid, testSess.NodeSessions[nid], conf, srvTrans, testSess.NodeSessions[nid].ObjectStore)
					if err != nil {
						t.Fatal(err)
					}
					cli.Coordinator = coord.NewNodeCoordinator(nid)
					clou.Service.Register(nid)
					clients[nid] = cli
					all[nid] = cli
				}

				sd := Description{
					Cpk: sessParams.Nodes,
					GaloisKeys: []struct {
						GaloisEl  uint64
						Receivers []pkg.NodeID
					}{
						{5, []pkg.NodeID{hid}},
						{25, []pkg.NodeID{hid}},
						{125, []pkg.NodeID{hid}},
					},
					Rlk: []pkg.NodeID{hid},
				}

				// runs the setup
				go func() {
					sigList, _ := DescriptionToSignatureList(sd)
					for _, sig := range sigList {
						clou.RunSignature(ctx, sig)
					}
					coord.Close()
				}()

				// run the nodes
				g, ctx := errgroup.WithContext(ctx)
				for nid, node := range all {
					nid := nid
					node := node
					g.Go(func() error {
						err := node.Run(ctx, node.Coordinator)
						return errors.WithMessagef(err, "error at node %s", nid)
					})
				}
				err = g.Wait()
				require.Nil(t, err)

				for _, n := range all {
					CheckTestSetup(ctx, t, n.self, testSess, sd, n)
				}

				// 	// Start public key generation
				// 	t.Run("DelayedSetup", func(t *testing.T) {

				// 		g := new(errgroup.Group)

				// 		// runs the cloud
				// 		g.Go(func() error {

				// 			errExec := clou.Service.RunProtocol(ctx, pd)
				// 			if errExec != nil {
				// 				errExec = fmt.Errorf("helper error: %w", errExec)
				// 			}
				// 			return errExec
				// 		})

				// 		// This test simulate erratic peer nodes that may not be online when the
				// 		// setup begins (but connect eventually).
				// 		nDelayed := ts.N - ts.T
				// 		if ts.N == ts.T {
				// 			nDelayed = 1
				// 		}
				// 		split := len(clients) - nDelayed
				// 		online, delayed := utils.NewSet(clients[:split]), utils.NewSet(clients[split:])

				// 		// runs the online clients
				// 		for c := range online {
				// 			c := c
				// 			g.Go(func() error {
				// 				errExec := c.Execute(ctx, sd)
				// 				if errExec != nil {
				// 					errExec = fmt.Errorf("client (%s) error: %w", c.Node.ID(), errExec)
				// 				}
				// 				return errExec
				// 			})
				// 		}

				// 		// if T < N, the online parties should be able to complete the setup
				// 		// by themselves, so we wait for them to finish and check their
				// 		// sessions. Otherwise, we wait for a bit before running the others.
				// 		if len(online) >= ts.T {
				// 			err = g.Wait()
				// 			if err != nil {
				// 				t.Fatal(err)
				// 			}
				// 			checkKeyGenProt(t, localTest, sd, clou)
				// 			for c := range online {
				// 				checkKeyGenProt(t, localTest, sd, &c)
				// 			}
				// 		} else {
				// 			<-time.After(time.Second >> 4)
				// 		}

				// 		// runs the delayed clients
				// 		for c := range delayed {
				// 			c := c
				// 			g.Go(func() error {
				// 				errExec := c.Execute(ctx, sd)
				// 				if errExec != nil {
				// 					errExec = fmt.Errorf("client (%s) error: %w", c.Node.ID(), errExec)
				// 				}
				// 				return errExec
				// 			})
				// 		}
				// 		err = g.Wait()
				// 		if err != nil {
				// 			t.Fatal(err)
				// 		}

				// 		checkKeyGenProt(t, localTest, sd, clou)
				// 		for _, node := range clients {
				// 			checkKeyGenProt(t, localTest, sd, &node)
				// 		}
				// 	})
			})
		}
	}
}

func checkResultInSession(t *testing.T, sess *pkg.Session, sign protocols.Signature, expectedPresence bool) {
	present, err := sess.IsPresent(sign.String())
	if err != nil {
		panic("Error in IsPresent")
	}

	require.Equal(t, expectedPresence, present)
}
