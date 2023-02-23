package setup_test

import (
	"fmt"
	"math"
	"math/bits"
	"testing"
	"time"

	"github.com/ldsec/helium/pkg/utils"

	"github.com/ldsec/helium/pkg/node"
	"github.com/ldsec/helium/pkg/services/setup"
	pkg "github.com/ldsec/helium/pkg/session"

	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"golang.org/x/sync/errgroup"
)

var rangeParam = []rlwe.ParametersLiteral{rlwe.TestPN12QP109 /* rlwe.TestPN13QP218 , rlwe.TestPN14QP438, rlwe.TestPN15QP880*/}

type testSetting struct {
	N int // N - total parties
	T int // T - parties in the access structure
}

var testSettings = []testSetting{
	{N: 2},
	{N: 3},
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

				var testConfig = node.LocalTestConfig{
					HelperNodes: 1, // the cloud
					LightNodes:  ts.N,
					Session: &node.SessionParameters{
						RLWEParams: literalParams,
						T:          ts.T,
					},
					DoThresholdSetup: true, // no t-out-of-N TSK gen in the cloud-based model yet
				}
				localTest := node.NewLocalTest(testConfig)

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
					Session: &node.SessionParameters{
						RLWEParams: literalParams,
						T:          ts.T,
					},
					DoThresholdSetup: true,
				}
				localTest := node.NewLocalTest(testConfig)

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
func checkKeyGenProt(t *testing.T, lt *node.LocalTest, setup setup.Description, sess *pkg.Session) {

	params := lt.Params
	sk := lt.SkIdeal
	nParties := len(lt.SessionNodes())

	if utils.NewSet(setup.Cpk).Contains(sess.NodeID) {
		pk := sess.PublicKey
		if pk == nil {
			t.Fatalf("pk was not generated for node %s", sess.NodeID)
		}
		log2BoundPk := bits.Len64(uint64(nParties) * params.NoiseBound() * uint64(params.N()))
		require.True(t, rlwe.PublicKeyIsCorrect(pk, sk, params, log2BoundPk))
	}

	for _, key := range setup.GaloisKeys {
		if utils.NewSet(key.Receivers).Contains(sess.NodeID) {
			rtk, isGen := sess.EvaluationKey.Rtks.Keys[key.GaloisEl]
			if !isGen {
				t.Fatalf("rtk was not generated for node %s", sess.NodeID)
			}
			log2BoundRtk := bits.Len64(uint64(
				params.N() * len(rtk.Value) * len(rtk.Value[0]) *
					(params.N()*3*int(math.Floor(rlwe.DefaultSigma*6)) +
						2*3*int(math.Floor(rlwe.DefaultSigma*6)) + params.N()*3)))
			require.True(t, rlwe.RotationKeyIsCorrect(rtk, key.GaloisEl, sk, params, log2BoundRtk), "rtk for galEl %d should be correct", key.GaloisEl)
		}
	}

	if utils.NewSet(setup.Rlk).Contains(sess.NodeID) {
		rlk := sess.RelinearizationKey
		if rlk == nil {
			t.Fatalf("rlk was not generated for node %s", sess.NodeID)
		}

		levelQ, levelP := params.QCount()-1, params.PCount()-1
		decompSize := params.DecompPw2(levelQ, levelP) * params.DecompRNS(levelQ, levelP)
		log2BoundRlk := bits.Len64(uint64(
			params.N() * decompSize * (params.N()*3*int(params.NoiseBound()) +
				2*3*int(params.NoiseBound()) + params.N()*3)))
		require.True(t, rlwe.RelinearizationKeyIsCorrect(rlk.Keys[0], sk, params, log2BoundRlk))
	}
}
