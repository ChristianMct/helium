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
	return tt.helperSrv.GetProtocolOutput(ctx, pd)
}

// TestCloudAssistedSetup tests the setup service in cloud-assisted mode with one helper and N light nodes.
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

				peconf := protocols.ExecutorConfig{
					SigQueueSize:     300,
					MaxProtoPerNode:  1,
					MaxAggregation:   1,
					MaxParticipation: 1,
				}

				srvTrans := &testNodeTrans{Transport: protoTrans}
				clou.Service, err = NewSetupService(hid, testSess.HelperSession, peconf, srvTrans, testSess.HelperSession.ObjectStore)
				if err != nil {
					t.Fatal(err)
				}
				clou.Coordinator = coord

				clients := make(map[pkg.NodeID]*testnode, ts.N)
				for nid := range nids {
					cli := &testnode{}
					cli.Session = testSess.NodeSessions[nid]
					srvTrans := &testNodeTrans{Transport: protoTrans.TransportFor(nid), helperSrv: clou.Service}
					cli.Service, err = NewSetupService(nid, testSess.NodeSessions[nid], peconf, srvTrans, testSess.NodeSessions[nid].ObjectStore)
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

				// 		// This test simulate erratic light nodes that may not be online when the
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

// // TestSetupPublicKeyExchange executes the setup protocol with an external receiver that sends its public key to all nodes.
// func TestSetupPublicKeyExchange(t *testing.T) {
// 	literalParams := rangeParam[0]

// 	t.Run(fmt.Sprintf("NParty=%d/T=%d/logN=%d", testSettings[1].N, testSettings[1].N, literalParams.LogN), func(t *testing.T) {

// 		var sessParams = &pkg.SessionParameters{
// 			RLWEParams: literalParams,
// 			T:          testSettings[1].N,
// 		}
// 		var testConfig = node.LocalTestConfig{
// 			HelperNodes:   1,                 // the cloud
// 			LightNodes:    testSettings[1].N, // node_0, node_1, node_2
// 			ExternalNodes: 1,                 // node_R
// 			Session:       sessParams,
// 			//DoThresholdSetup: true, // no t-out-of-N TSK gen in the cloud-based model yet
// 		}
// 		localTest := node.NewLocalTest(testConfig)
// 		defer func() {
// 			err := localTest.Close()
// 			if err != nil {
// 				panic(err)
// 			}
// 		}()

// 		var err error
// 		cloud := localTest.HelperNodes[0]
// 		cloudss, ok := cloud.GetSessionFromID("test-session")
// 		if !ok {
// 			t.Fatal("session should exist")
// 		}
// 		// log.Printf(cloudss.String())

// 		// receiver for PCKS
// 		node_R := localTest.ExternalNodes[0]
// 		node_Rsess, ok := node_R.GetSessionFromID("test-session")
// 		if !ok {
// 			t.Fatal("session should exist")
// 		}

// 		// session nodes + external receiver
// 		sessionNodes := localTest.SessionNodes()
// 		clients := make([]*node.Node, len(sessionNodes))
// 		for i := range clients {
// 			clients[i] = sessionNodes[i]
// 		}
// 		clients = append(clients, node_R)

// 		setup := Description{
// 			Cpk: localTest.SessionNodesIds(),
// 			Pk: []struct {
// 				Sender    pkg.NodeID
// 				Receivers []pkg.NodeID
// 			}{
// 				{node_R.ID(), localTest.SessionNodesIds()},
// 			},
// 		}

// 		localTest.Start()

// 		// Start public key generation
// 		t.Run("FullSetup", func(t *testing.T) {

// 			g := new(errgroup.Group)

// 			// run the cloud
// 			g.Go(func() error {
// 				errExec := cloud.GetSetupService().Execute(setup, localTest.NodesList)
// 				if errExec != nil {
// 					errExec = fmt.Errorf("cloud (%s) error: %w", cloud.ID(), errExec)
// 				}
// 				return errExec
// 			})

// 			// run clients
// 			for _, client := range clients {
// 				client := client
// 				g.Go(func() error {
// 					errExec := client.GetSetupService().Execute(setup, localTest.NodesList)
// 					if errExec != nil {
// 						errExec = fmt.Errorf("client (%s) error: %w", client.ID(), errExec)
// 					}
// 					return errExec
// 				})
// 			}

// 			// wait for cloud and client to finish running the setup
// 			err = g.Wait()
// 			if err != nil {
// 				t.Fatal(err)
// 			}

// 			// check if setup material was correctly generated
// 			outputSk, err := node_Rsess.GetSecretKey()
// 			if err != nil {
// 				t.Fatal(err)
// 			}
// 			checkKeyGenProt(t, localTest, setup, cloudss, outputSk)

// 			for _, client := range clients {
// 				clientss, ok := client.GetSessionFromID("test-session")
// 				if !ok {
// 					t.Fatal("session should exist")
// 				}
// 				checkKeyGenProt(t, localTest, setup, clientss, outputSk)
// 			}
// 		})
// 	})
// }

// TestQuery executes the setup protocol with one client and the cloud. Then checks that each party queries ONLY the keys specified in
// the setup descriptor.
// func TestQuery(t *testing.T) {
// 	literalParams := rangeParam[0]
// 	ts := testSetting{
// 		N: 2,
// 		T: 2,
// 	}

// 	t.Run(fmt.Sprintf("NParty=%d/T=%d/logN=%d", ts.N, ts.T, literalParams.LogN), func(t *testing.T) {
// 		var sessParams = &pkg.SessionParameters{
// 			RLWEParams: literalParams,
// 			T:          ts.T,
// 		}
// 		var testConfig = node.LocalTestConfig{
// 			HelperNodes: 1,
// 			LightNodes:  ts.N,
// 			Session:     sessParams,
// 			//DoThresholdSetup: true,
// 		}
// 		localTest := node.NewLocalTest(testConfig)
// 		defer func() {
// 			err := localTest.Close()
// 			if err != nil {
// 				panic(err)
// 			}
// 		}()

// 		var err error
// 		cloud := localTest.HelperNodes[0]
// 		clients := localTest.SessionNodes()

// 		setup := Description{
// 			Cpk: localTest.SessionNodesIds(),
// 			Rlk: []pkg.NodeID{cloud.ID()},
// 			GaloisKeys: []struct {
// 				GaloisEl  uint64
// 				Receivers []pkg.NodeID
// 			}{
// 				{5, []pkg.NodeID{clients[1].ID()}},
// 				{25, []pkg.NodeID{cloud.ID()}},
// 				{125, localTest.SessionNodesIds()},
// 			},
// 		}

// 		localTest.Start()

// 		// Start public key generation
// 		t.Run("FullSetup", func(t *testing.T) {

// 			g := new(errgroup.Group)

// 			// run the cloud
// 			g.Go(func() error {
// 				errExec := cloud.GetSetupService().Execute(setup, localTest.NodesList)
// 				if errExec != nil {
// 					errExec = fmt.Errorf("cloud (%s) error: %w", cloud.ID(), errExec)
// 				}
// 				return errExec
// 			})

// 			// run the client
// 			for _, client := range clients {
// 				client := client
// 				g.Go(func() error {
// 					errExec := client.GetSetupService().Execute(setup, localTest.NodesList)
// 					if errExec != nil {
// 						errExec = fmt.Errorf("client (%s) error: %w", client.ID(), errExec)
// 					}
// 					return errExec
// 				})
// 			}

// 			// wait for cloud and client to finish running the setup
// 			err = g.Wait()
// 			if err != nil {
// 				t.Fatal(err)
// 			}

// 			light0Sess, ok := clients[0].GetSessionFromID("test-session")
// 			if !ok {
// 				t.Fatal("session should exist")
// 			}
// 			light1Sess, ok := clients[1].GetSessionFromID("test-session")
// 			if !ok {
// 				t.Fatal("session should exist")
// 			}

// 			// cpk: {light-0}
// 			checkResultInSession(t, light0Sess, protocols.Signature{Type: protocols.CKG}, true)
// 			checkResultInSession(t, light1Sess, protocols.Signature{Type: protocols.CKG}, true)

// 			// rlk: {light-0, light-1}
// 			checkResultInSession(t, light0Sess, protocols.Signature{Type: protocols.RKG_2}, false)
// 			checkResultInSession(t, light1Sess, protocols.Signature{Type: protocols.RKG_2}, false)

// 			// rtk[5]: {light-1}
// 			checkResultInSession(t, light0Sess, protocols.Signature{Type: protocols.RTG, Args: map[string]string{"GalEl": strconv.FormatUint(5, 10)}}, false)
// 			checkResultInSession(t, light1Sess, protocols.Signature{Type: protocols.RTG, Args: map[string]string{"GalEl": strconv.FormatUint(5, 10)}}, true)

// 			// rtk[25]: {}
// 			checkResultInSession(t, light0Sess, protocols.Signature{Type: protocols.RTG, Args: map[string]string{"GalEl": strconv.FormatUint(25, 10)}}, false)
// 			checkResultInSession(t, light1Sess, protocols.Signature{Type: protocols.RTG, Args: map[string]string{"GalEl": strconv.FormatUint(25, 10)}}, false)

// 			// rtk[125]: {light-0, light-1}
// 			checkResultInSession(t, light0Sess, protocols.Signature{Type: protocols.RTG, Args: map[string]string{"GalEl": strconv.FormatUint(125, 10)}}, true)
// 			checkResultInSession(t, light1Sess, protocols.Signature{Type: protocols.RTG, Args: map[string]string{"GalEl": strconv.FormatUint(125, 10)}}, true)
// 		})
// 	})
// }

// // TestPeerToPeerSetup tests the peer to peer setup with N full nodes.
// func TestPeerToPeerSetup(t *testing.T) {

// 	t.Skip("skipped: current version focuses on cloud-based model")

// 	for _, literalParams := range rangeParam {
// 		for _, ts := range testSettings {

// 			if ts.T == 0 {
// 				ts.T = ts.N // N-out-of-N scenario
// 			}

// 			t.Run(fmt.Sprintf("NParty=%d/T=%d/logN=%d", ts.N, ts.T, literalParams.LogN), func(t *testing.T) {

// 				var testConfig = node.LocalTestConfig{
// 					FullNodes:  ts.N,
// 					LightNodes: 0,
// 					Session: &pkg.SessionParameters{
// 						RLWEParams: literalParams,
// 						T:          ts.T,
// 					},
// 					//DoThresholdSetup: true,
// 				}
// 				localTest := node.NewLocalTest(testConfig)
// 				defer func() {
// 					err := localTest.Close()
// 					if err != nil {
// 						panic(err)
// 					}
// 				}()

// 				params := localTest.Params
// 				peerIds := localTest.NodeIds()
// 				sd := Description{
// 					Cpk: localTest.SessionNodesIds(),
// 					GaloisKeys: []struct {
// 						GaloisEl  uint64
// 						Receivers []pkg.NodeID
// 					}{
// 						{5, localTest.SessionNodesIds()},
// 						{25, localTest.SessionNodesIds()},
// 						{125, localTest.SessionNodesIds()},
// 					},
// 					Rlk: localTest.SessionNodesIds(),
// 				}

// 				var err error

// 				nodes := make(map[pkg.NodeID]*peer, ts.N)
// 				// initialise nodes, sessions and load protocols
// 				for _, n := range localTest.Nodes {
// 					n := &peer{Node: n}

// 					n.Service = n.Node.GetSetupService()
// 					if err != nil {
// 						t.Error(err)
// 					}

// 					nodes[n.ID()] = n
// 				}

// 				localTest.Start()

// 				// launch public key generation and check correctness
// 				t.Run("FullSetup", func(t *testing.T) {

// 					g := new(errgroup.Group)

// 					for _, id := range peerIds {
// 						node := nodes[id]

// 						g.Go(
// 							func() error {
// 								return node.Service.Execute(sd, localTest.NodesList)
// 							},
// 						)

// 					}
// 					err = g.Wait()
// 					if err != nil {
// 						t.Fatal(err)
// 					}

// 					// Checks that a random client set of size T can reconstruct the ideal secret-key
// 					grp := pkg.GetRandomClientSlice(testConfig.Session.T, localTest.NodeIds())
// 					skagg := rlwe.NewSecretKey(params)
// 					for _, nodeid := range grp {
// 						node := nodes[nodeid]
// 						sess, _ := node.GetSessionFromID("test-session")
// 						skp, errSk := sess.SecretKeyForGroup(grp)

// 						if errSk != nil {
// 							panic(errSk)
// 						}
// 						localTest.Params.RingQP().AddLvl(skagg.LevelQ(), skagg.LevelP(), skp.Value, skagg.Value, skagg.Value)
// 					}
// 					require.True(t, localTest.Params.RingQ().Equal(skagg.Value.Q, localTest.SkIdeal.Value.Q))
// 					require.True(t, localTest.Params.RingP().Equal(skagg.Value.P, localTest.SkIdeal.Value.P))

// 					// checks that all nodes have a complete setup
// 					for _, node := range nodes {
// 						// node.PrintNetworkStats()
// 						sess, _ := node.GetSessionFromID("test-session")
// 						checkKeyGenProt(t, localTest, sd, sess)
// 					}
// 				})
// 			})
// 		}
// 	}
// }
