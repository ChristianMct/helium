package setup_test

import (
	"fmt"
	"math"
	"math/bits"
	"strconv"
	"testing"
	"time"

	"github.com/ldsec/helium/pkg/protocols"
	"github.com/ldsec/helium/pkg/session/objectstore"
	"github.com/ldsec/helium/pkg/utils"

	"github.com/ldsec/helium/pkg/node"
	"github.com/ldsec/helium/pkg/services/setup"
	pkg "github.com/ldsec/helium/pkg/session"

	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"golang.org/x/sync/errgroup"
)

var DBPath = "./SetupProtocolDB"

var rangeParam = []rlwe.ParametersLiteral{rlwe.TestPN12QP109 /* rlwe.TestPN13QP218 , rlwe.TestPN14QP438, rlwe.TestPN15QP880*/}

type testSetting struct {
	N int // N - total parties
	T int // T - parties in the access structure
}

var testSettings = []testSetting{
	// {N: 2},
	// {N: 3},
	{N: 3, T: 2},
}

type peer struct {
	*node.Node
	*setup.Service
}

type cloud struct {
	*node.Node
	*setup.Service
	*pkg.Session
}

type lightNode struct {
	*node.Node
	*setup.Service
	*pkg.Session
}

// TestCloudAssistedSetup tests the setup service in cloud-assisted mode with one helper and N light nodes.
func TestCloudAssistedSetup(t *testing.T) {
	for _, literalParams := range rangeParam {
		for _, ts := range testSettings {
			if ts.T == 0 {
				ts.T = ts.N // N-out-of-N scenario
			}

			t.Run(fmt.Sprintf("NParty=%d/T=%d/logN=%d", ts.N, ts.T, literalParams.LogN), func(t *testing.T) {

				var testname = fmt.Sprintf("TestCloudAssistedSetup-NParty=%dT=%dlogN=%d", ts.N, ts.T, literalParams.LogN)

				var objstoreconf = objectstore.Config{
					BackendName: "mem",
					DBPath:      fmt.Sprintf("%s/%s", DBPath, testname),
				}
				var sessParams = &pkg.SessionParameters{
					RLWEParams:        literalParams,
					T:                 ts.T,
					ObjectStoreConfig: objstoreconf,
				}
				var testConfig = node.LocalTestConfig{
					HelperNodes:      1, // the cloud
					LightNodes:       ts.N,
					Session:          sessParams,
					DoThresholdSetup: true, // no t-out-of-N TSK gen in the cloud-based model yet
				}

				localTest := node.NewLocalTest(testConfig)
				defer func() {
					err := localTest.Close()
					if err != nil {
						panic(err)
					}
				}()

				var err error
				var ok bool
				clou := &cloud{Node: localTest.HelperNodes[0]}
				clou.Service = clou.GetSetupService()
				if err != nil {
					t.Error(err)
				}
				clou.Session, ok = clou.GetSessionFromID("test-session")
				if !ok {
					t.Fatal("session should exist")
				}

				// initialise clients
				allNodes := []*setup.Service{clou.Service}
				clients := make([]lightNode, ts.N)
				sessionNodes := localTest.SessionNodes()
				for i := range clients {
					clients[i].Node = sessionNodes[i]
					clients[i].Service = clients[i].GetSetupService()
					clients[i].Session, ok = clients[i].GetSessionFromID("test-session")
					if !ok {
						t.Fatal("session should exist")
					}
					if err != nil {
						t.Fatal(err)
					}
					allNodes = append(allNodes, clients[i].Service)
				}

				setup := setup.Description{
					Cpk: localTest.SessionNodesIds(),
					GaloisKeys: []struct {
						GaloisEl  uint64
						Receivers []pkg.NodeID
					}{
						{5, []pkg.NodeID{clou.Node.ID()}},
						{25, []pkg.NodeID{clou.Node.ID()}},
						{125, []pkg.NodeID{clou.Node.ID()}},
					},
					Rlk: []pkg.NodeID{clou.Node.ID()},
				}

				localTest.Start()

				// Start public key generation
				t.Run("FullSetup", func(t *testing.T) {

					g := new(errgroup.Group)

					// runs the cloud
					g.Go(func() error {
						errExec := clou.Execute(setup, localTest.NodesList)
						if errExec != nil {
							errExec = fmt.Errorf("cloud (%s) error: %w", clou.Node.ID(), errExec)
						}
						return errExec
					})

					// This test simulate erratic light nodes that may not be online when the
					// setup begins (but connect eventually).
					nDelayed := ts.N - ts.T
					if ts.N == ts.T {
						nDelayed = 1
					}
					split := len(clients) - nDelayed
					online, delayed := utils.NewSet(clients[:split]), utils.NewSet(clients[split:])

					// runs the online clients
					for c := range online {
						c := c
						g.Go(func() error {
							errExec := c.Execute(setup, localTest.NodesList)
							if errExec != nil {
								errExec = fmt.Errorf("client (%s) error: %w", c.Node.ID(), errExec)
							}
							return errExec
						})
					}

					// if T < N, the online parties should be able to complete the setup
					// by themselves, so we wait for them to finish and check their
					// sessions. Otherwise, we wait for a bit before running the others.
					if len(online) >= ts.T {
						err = g.Wait()
						if err != nil {
							t.Fatal(err)
						}
						checkKeyGenProt(t, localTest, setup, clou.Session)
						for c := range online {
							checkKeyGenProt(t, localTest, setup, c.Session)
						}
					} else {
						<-time.After(time.Second >> 4)
					}

					// runs the delayed clients
					for c := range delayed {
						c := c
						g.Go(func() error {
							errExec := c.Execute(setup, localTest.NodesList)
							if errExec != nil {
								errExec = fmt.Errorf("client (%s) error: %w", c.Node.ID(), errExec)
							}
							return errExec
						})
					}
					err = g.Wait()
					if err != nil {
						t.Fatal(err)
					}

					checkKeyGenProt(t, localTest, setup, clou.Session)
					for _, node := range clients {
						checkKeyGenProt(t, localTest, setup, node.Session)
					}
				})
			})
		}
	}
}

// TestCloudAssistedSetupSkinny tests the setup service in cloud-assisted mode with one helper and N light nodes.
// This test is a simplified version of the TestCloudAssistedSetup test.
func TestSkinnyCloudAssistedSetup(t *testing.T) {
	for _, literalParams := range rangeParam {
		for _, ts := range testSettings {
			if ts.T == 0 {
				ts.T = ts.N // N-out-of-N scenario
			}

			t.Run(fmt.Sprintf("NParty=%d/T=%d/logN=%d", ts.N, ts.T, literalParams.LogN), func(t *testing.T) {

				var testname = fmt.Sprintf("TestCloudAssistedSetupSkinny-NParty=%dT=%dlogN=%d", ts.N, ts.T, literalParams.LogN)

				var objstoreconf = objectstore.Config{
					BackendName: "mem",
					DBPath:      fmt.Sprintf("%s/%s", DBPath, testname),
				}

				var sessParams = &pkg.SessionParameters{
					RLWEParams:        literalParams,
					T:                 ts.T,
					ObjectStoreConfig: objstoreconf,
				}
				var testConfig = node.LocalTestConfig{
					HelperNodes:      1, // the cloud
					LightNodes:       ts.N,
					Session:          sessParams,
					DoThresholdSetup: true, // no t-out-of-N TSK gen in the cloud-based model yet
				}
				localTest := node.NewLocalTest(testConfig)
				defer func() {
					err := localTest.Close()
					if err != nil {
						panic(err)
					}
				}()

				var err error
				cloud := localTest.HelperNodes[0]
				clients := localTest.SessionNodes()

				setup := setup.Description{
					Cpk: localTest.SessionNodesIds(),
					GaloisKeys: []struct {
						GaloisEl  uint64
						Receivers []pkg.NodeID
					}{
						{5, []pkg.NodeID{cloud.ID()}},
						{25, []pkg.NodeID{cloud.ID()}},
						{125, []pkg.NodeID{cloud.ID()}},
					},
					Rlk: []pkg.NodeID{cloud.ID()},
				}

				localTest.Start()

				// Start public key generation
				t.Run("FullSetup", func(t *testing.T) {

					g := new(errgroup.Group)

					// runs the cloud
					g.Go(func() error {
						errExec := cloud.GetSetupService().Execute(setup, localTest.NodesList)
						if errExec != nil {
							errExec = fmt.Errorf("cloud (%s) error: %w", cloud.ID(), errExec)
						}
						return errExec
					})

					// runs the online clients
					for _, client := range clients {
						client := client
						g.Go(func() error {
							errExec := client.GetSetupService().Execute(setup, localTest.NodesList)
							if errExec != nil {
								errExec = fmt.Errorf("client (%s) error: %w", client.ID(), errExec)
							}
							return errExec
						})
					}

					// if T < N, the online parties should be able to complete the setup
					// by themselves, so we wait for them to finish and check their
					// sessions. Otherwise, we wait for a bit before running the others.
					// if len(online) >= ts.T {
					err = g.Wait()
					if err != nil {
						t.Fatal(err)
					}
					cloudss, ok := cloud.GetSessionFromID("test-session")
					if !ok {
						t.Fatal("session should exist")
					}
					checkKeyGenProt(t, localTest, setup, cloudss)

					for _, client := range clients {
						clientss, ok := client.GetSessionFromID("test-session")
						if !ok {
							t.Fatal("session should exist")
						}
						checkKeyGenProt(t, localTest, setup, clientss)
					}
				})
			})
		}
	}
}

// TestSimpleSetup executes the setup protocol with one client and the cloud. In this test, only the CPK is generated.
func TestSimpleSetup(t *testing.T) {
	literalParams := rangeParam[0]
	ts := testSetting{
		N: 1,
		T: 1,
	}

	t.Run(fmt.Sprintf("NParty=%d/T=%d/logN=%d", ts.N, ts.T, literalParams.LogN), func(t *testing.T) {

		var testname = fmt.Sprintf("TestSimpleSetup-NParty=%dT=%dlogN=%d", ts.N, ts.T, literalParams.LogN)

		var objstoreconf = objectstore.Config{
			BackendName: "mem",
			DBPath:      fmt.Sprintf("%s/%s", DBPath, testname),
		}

		var sessParams = &pkg.SessionParameters{
			RLWEParams:        literalParams,
			T:                 ts.T,
			ObjectStoreConfig: objstoreconf,
		}
		var testConfig = node.LocalTestConfig{
			HelperNodes:      1, // the cloud
			LightNodes:       ts.N,
			Session:          sessParams,
			DoThresholdSetup: true, // no t-out-of-N TSK gen in the cloud-based model yet
		}
		localTest := node.NewLocalTest(testConfig)
		defer func() {
			err := localTest.Close()
			if err != nil {
				panic(err)
			}
		}()

		var err error
		cloud := localTest.HelperNodes[0]
		client := localTest.SessionNodes()[0]

		setup := setup.Description{
			Cpk: localTest.SessionNodesIds(),
		}

		localTest.Start()

		// Start public key generation
		t.Run("FullSetup", func(t *testing.T) {

			g := new(errgroup.Group)

			// run the cloud
			g.Go(func() error {
				errExec := cloud.GetSetupService().Execute(setup, localTest.NodesList)
				if errExec != nil {
					errExec = fmt.Errorf("cloud (%s) error: %w", cloud.ID(), errExec)
				}
				return errExec
			})

			// run the client
			g.Go(func() error {
				errExec := client.GetSetupService().Execute(setup, localTest.NodesList)
				if errExec != nil {
					errExec = fmt.Errorf("client (%s) error: %w", client.ID(), errExec)
				}
				return errExec
			})

			// wait for cloud and client to finish running the setup
			err = g.Wait()
			if err != nil {
				t.Fatal(err)
			}

			// check if setup material was correctly generated
			cloudss, ok := cloud.GetSessionFromID("test-session")
			if !ok {
				t.Fatal("session should exist")
			}
			checkKeyGenProt(t, localTest, setup, cloudss)

			clientss, ok := client.GetSessionFromID("test-session")
			if !ok {
				t.Fatal("session should exist")
			}
			checkKeyGenProt(t, localTest, setup, clientss)
		})
	})
}

// TestSetupPublicKeyExchange executes the setup protocol with an external receiver that sends its public key to all nodes.
func TestSetupPublicKeyExchange(t *testing.T) {
	literalParams := rangeParam[0]

	t.Run(fmt.Sprintf("NParty=%d/T=%d/logN=%d", testSettings[1].N, testSettings[1].N, literalParams.LogN), func(t *testing.T) {

		var sessParams = &pkg.SessionParameters{
			RLWEParams: literalParams,
			T:          testSettings[1].N,
		}
		var testConfig = node.LocalTestConfig{
			HelperNodes:      1,                 // the cloud
			LightNodes:       testSettings[1].N, // node_0, node_1, node_2
			ExternalNodes:    1,                 // node_R
			Session:          sessParams,
			DoThresholdSetup: true, // no t-out-of-N TSK gen in the cloud-based model yet
		}
		localTest := node.NewLocalTest(testConfig)
		defer func() {
			err := localTest.Close()
			if err != nil {
				panic(err)
			}
		}()

		var err error
		cloud := localTest.HelperNodes[0]
		cloudss, ok := cloud.GetSessionFromID("test-session")
		if !ok {
			t.Fatal("session should exist")
		}
		// log.Printf(cloudss.String())

		// receiver for PCKS
		node_R := localTest.ExternalNodes[0]
		node_Rsess, ok := node_R.GetSessionFromID("test-session")
		if !ok {
			t.Fatal("session should exist")
		}

		// session nodes + external receiver
		sessionNodes := localTest.SessionNodes()
		clients := make([]*node.Node, len(sessionNodes))
		for i := range clients {
			clients[i] = sessionNodes[i]
		}
		clients = append(clients, node_R)

		setup := setup.Description{
			Cpk: localTest.SessionNodesIds(),
			Pk: []struct {
				Sender    pkg.NodeID
				Receivers []pkg.NodeID
			}{
				{node_R.ID(), localTest.SessionNodesIds()},
			},
		}

		localTest.Start()

		// Start public key generation
		t.Run("FullSetup", func(t *testing.T) {

			g := new(errgroup.Group)

			// run the cloud
			g.Go(func() error {
				errExec := cloud.GetSetupService().Execute(setup, localTest.NodesList)
				if errExec != nil {
					errExec = fmt.Errorf("cloud (%s) error: %w", cloud.ID(), errExec)
				}
				return errExec
			})

			// run clients
			for _, client := range clients {
				client := client
				g.Go(func() error {
					errExec := client.GetSetupService().Execute(setup, localTest.NodesList)
					if errExec != nil {
						errExec = fmt.Errorf("client (%s) error: %w", client.ID(), errExec)
					}
					return errExec
				})
			}

			// wait for cloud and client to finish running the setup
			err = g.Wait()
			if err != nil {
				t.Fatal(err)
			}

			// check if setup material was correctly generated
			outputSk, err := node_Rsess.GetOutputSk()
			if err != nil {
				t.Fatal(err)
			}
			checkKeyGenProt(t, localTest, setup, cloudss, outputSk)

			for _, client := range clients {
				clientss, ok := client.GetSessionFromID("test-session")
				if !ok {
					t.Fatal("session should exist")
				}
				checkKeyGenProt(t, localTest, setup, clientss, outputSk)
			}
		})
	})
}

// TestQuery executes the setup protocol with one client and the cloud. Then checks that each party queries ONLY the keys specified in
// the setup descriptor.
func TestQuery(t *testing.T) {
	literalParams := rangeParam[0]
	ts := testSetting{
		N: 2,
		T: 2,
	}

	t.Run(fmt.Sprintf("NParty=%d/T=%d/logN=%d", ts.N, ts.T, literalParams.LogN), func(t *testing.T) {
		var sessParams = &pkg.SessionParameters{
			RLWEParams: literalParams,
			T:          ts.T,
		}
		var testConfig = node.LocalTestConfig{
			HelperNodes:      1,
			LightNodes:       ts.N,
			Session:          sessParams,
			DoThresholdSetup: true,
		}
		localTest := node.NewLocalTest(testConfig)
		defer func() {
			err := localTest.Close()
			if err != nil {
				panic(err)
			}
		}()

		var err error
		cloud := localTest.HelperNodes[0]
		clients := localTest.SessionNodes()

		setup := setup.Description{
			Cpk: []pkg.NodeID{clients[0].ID()},
			Rlk: localTest.SessionNodesIds(),
			GaloisKeys: []struct {
				GaloisEl  uint64
				Receivers []pkg.NodeID
			}{
				{5, []pkg.NodeID{clients[1].ID()}},
				{25, []pkg.NodeID{cloud.ID()}},
				{125, localTest.SessionNodesIds()},
			},
		}

		localTest.Start()

		// Start public key generation
		t.Run("FullSetup", func(t *testing.T) {

			g := new(errgroup.Group)

			// run the cloud
			g.Go(func() error {
				errExec := cloud.GetSetupService().Execute(setup, localTest.NodesList)
				if errExec != nil {
					errExec = fmt.Errorf("cloud (%s) error: %w", cloud.ID(), errExec)
				}
				return errExec
			})

			// run the client
			for _, client := range clients {
				client := client
				g.Go(func() error {
					errExec := client.GetSetupService().Execute(setup, localTest.NodesList)
					if errExec != nil {
						errExec = fmt.Errorf("client (%s) error: %w", client.ID(), errExec)
					}
					return errExec
				})
			}

			// wait for cloud and client to finish running the setup
			err = g.Wait()
			if err != nil {
				t.Fatal(err)
			}

			light0Sess, ok := clients[0].GetSessionFromID("test-session")
			if !ok {
				t.Fatal("session should exist")
			}
			light1Sess, ok := clients[1].GetSessionFromID("test-session")
			if !ok {
				t.Fatal("session should exist")
			}

			// cpk: {light-0}
			checkResultInSession(t, light0Sess, protocols.Signature{Type: protocols.CKG}, true)
			checkResultInSession(t, light1Sess, protocols.Signature{Type: protocols.CKG}, false)

			// rlk: {light-0, light-1}
			checkResultInSession(t, light0Sess, protocols.Signature{Type: protocols.RKG}, true)
			checkResultInSession(t, light1Sess, protocols.Signature{Type: protocols.RKG}, true)

			// rtk[5]: {light-1}
			checkResultInSession(t, light0Sess, protocols.Signature{Type: protocols.RTG, Args: map[string]string{"GalEl": strconv.FormatUint(5, 10)}}, false)
			checkResultInSession(t, light1Sess, protocols.Signature{Type: protocols.RTG, Args: map[string]string{"GalEl": strconv.FormatUint(5, 10)}}, true)

			// rtk[25]: {}
			checkResultInSession(t, light0Sess, protocols.Signature{Type: protocols.RTG, Args: map[string]string{"GalEl": strconv.FormatUint(25, 10)}}, false)
			checkResultInSession(t, light1Sess, protocols.Signature{Type: protocols.RTG, Args: map[string]string{"GalEl": strconv.FormatUint(25, 10)}}, false)

			// rtk[125]: {light-0, light-1}
			checkResultInSession(t, light0Sess, protocols.Signature{Type: protocols.RTG, Args: map[string]string{"GalEl": strconv.FormatUint(125, 10)}}, true)
			checkResultInSession(t, light1Sess, protocols.Signature{Type: protocols.RTG, Args: map[string]string{"GalEl": strconv.FormatUint(125, 10)}}, true)
		})
	})
}

func checkResultInSession(t *testing.T, sess *pkg.Session, sign protocols.Signature, expectedPresence bool) {
	present, err := sess.IsPresent(sign.ToObjectStore())
	if err != nil {
		panic("Error in IsPresent")
	}

	require.Equal(t, present, expectedPresence)
}

// TestPeerToPeerSetup tests the peer to peer setup with N full nodes.
func TestPeerToPeerSetup(t *testing.T) {

	t.Skip("skipped: current version focuses on cloud-based model")

	for _, literalParams := range rangeParam {
		for _, ts := range testSettings {

			if ts.T == 0 {
				ts.T = ts.N // N-out-of-N scenario
			}

			t.Run(fmt.Sprintf("NParty=%d/T=%d/logN=%d", ts.N, ts.T, literalParams.LogN), func(t *testing.T) {

				var testConfig = node.LocalTestConfig{
					FullNodes:  ts.N,
					LightNodes: 0,
					Session: &pkg.SessionParameters{
						RLWEParams: literalParams,
						T:          ts.T,
					},
					DoThresholdSetup: true,
				}
				localTest := node.NewLocalTest(testConfig)
				defer func() {
					err := localTest.Close()
					if err != nil {
						panic(err)
					}
				}()

				params := localTest.Params
				peerIds := localTest.NodeIds()
				sd := setup.Description{
					Cpk: localTest.SessionNodesIds(),
					GaloisKeys: []struct {
						GaloisEl  uint64
						Receivers []pkg.NodeID
					}{
						{5, localTest.SessionNodesIds()},
						{25, localTest.SessionNodesIds()},
						{125, localTest.SessionNodesIds()},
					},
					Rlk: localTest.SessionNodesIds(),
				}

				var err error

				nodes := make(map[pkg.NodeID]*peer, ts.N)
				// initialise nodes, sessions and load protocols
				for _, n := range localTest.Nodes {
					n := &peer{Node: n}

					n.Service = n.Node.GetSetupService()
					if err != nil {
						t.Error(err)
					}

					nodes[n.ID()] = n
				}

				localTest.Start()

				// launch public key generation and check correctness
				t.Run("FullSetup", func(t *testing.T) {

					g := new(errgroup.Group)

					for _, id := range peerIds {
						node := nodes[id]

						g.Go(
							func() error {
								return node.Service.Execute(sd, localTest.NodesList)
							},
						)

					}
					err = g.Wait()
					if err != nil {
						t.Fatal(err)
					}

					// Checks that a random client set of size T can reconstruct the ideal secret-key
					grp := pkg.GetRandomClientSlice(testConfig.Session.T, localTest.NodeIds())
					skagg := rlwe.NewSecretKey(params)
					for _, nodeid := range grp {
						node := nodes[nodeid]
						sess, _ := node.GetSessionFromID("test-session")
						skp, errSk := sess.SecretKeyForGroup(grp)

						if errSk != nil {
							panic(errSk)
						}
						localTest.Params.RingQP().AddLvl(skagg.LevelQ(), skagg.LevelP(), skp.Value, skagg.Value, skagg.Value)
					}
					require.True(t, localTest.Params.RingQ().Equal(skagg.Value.Q, localTest.SkIdeal.Value.Q))
					require.True(t, localTest.Params.RingP().Equal(skagg.Value.P, localTest.SkIdeal.Value.P))

					// checks that all nodes have a complete setup
					for _, node := range nodes {
						// node.PrintNetworkStats()
						sess, _ := node.GetSessionFromID("test-session")
						checkKeyGenProt(t, localTest, sd, sess)
					}
				})
			})
		}
	}
}

// Based on the session information, check if the protocol was performed correctly.
func checkKeyGenProt(t *testing.T, lt *node.LocalTest, setup setup.Description, sess *pkg.Session, externalSk ...*rlwe.SecretKey) {

	params := lt.Params
	sk := lt.SkIdeal
	nParties := len(lt.SessionNodes())

	log2BoundPk := bits.Len64(uint64(nParties) * params.NoiseBound() * uint64(params.N()))

	// check CPK
	if utils.NewSet(setup.Cpk).Contains(sess.NodeID) {
		cpk, err := sess.GetCollectivePublicKey()
		if err != nil {
			t.Fatalf("%s | %s", sess.NodeID, err)
		}

		require.True(t, rlwe.PublicKeyIsCorrect(cpk, sk, params, log2BoundPk))
	}

	// check shared PK
	for _, key := range setup.Pk {
		if utils.NewSet(key.Receivers).Contains(sess.NodeID) {
			pk, err := sess.GetOutputPkForNode(key.Sender)
			if err != nil {
				t.Fatalf("%s | %s", sess.NodeID, err)
			}
			if externalSk == nil || len(externalSk) == 0 {
				t.Fatalf("%s | cannot check correctness of public key of %s", sess.NodeID, key.Sender)
			}
			require.True(t, rlwe.PublicKeyIsCorrect(pk, externalSk[0], params, log2BoundPk))
		}
	}

	// check RTG
	for _, key := range setup.GaloisKeys {
		if utils.NewSet(key.Receivers).Contains(sess.NodeID) {
			rtk, err := sess.GetRotationKey(key.GaloisEl)
			if err != nil {
				t.Fatalf("%s | %s", sess.NodeID, err)
			}
			log2BoundRtk := bits.Len64(uint64(
				params.N() * len(rtk.Value) * len(rtk.Value[0]) *
					(params.N()*3*int(math.Floor(rlwe.DefaultSigma*6)) +
						2*3*int(math.Floor(rlwe.DefaultSigma*6)) + params.N()*3)))
			require.True(t, rlwe.RotationKeyIsCorrect(rtk, key.GaloisEl, sk, params, log2BoundRtk), "rtk for galEl %d should be correct", key.GaloisEl)
		}
	}

	// check RLK
	if utils.NewSet(setup.Rlk).Contains(sess.NodeID) {
		rlk, err := sess.GetRelinearizationKey()
		if err != nil {
			t.Fatalf("%s | %s", sess.NodeID, err)
		}

		levelQ, levelP := params.QCount()-1, params.PCount()-1
		decompSize := params.DecompPw2(levelQ, levelP) * params.DecompRNS(levelQ, levelP)
		log2BoundRlk := bits.Len64(uint64(
			params.N() * decompSize * (params.N()*3*int(params.NoiseBound()) +
				2*3*int(params.NoiseBound()) + params.N()*3)))
		require.True(t, rlwe.RelinearizationKeyIsCorrect(rlk.Keys[0], sk, params, log2BoundRlk))
	}
}
