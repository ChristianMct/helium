package setup

import (
	"fmt"
	"math"
	"math/bits"
	"testing"

	"github.com/ldsec/helium/pkg/node"
	pkg "github.com/ldsec/helium/pkg/session"

	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"golang.org/x/sync/errgroup"
)

var rangeParam = []rlwe.ParametersLiteral{rlwe.TestPN12QP109, rlwe.TestPN13QP218 /*, rlwe.TestPN14QP438, rlwe.TestPN15QP880*/}

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
	*Service
}

type cloud struct {
	*node.Node
	*Service
}

type lightNode struct {
	*node.Node
	*Service
}

// TestCloudAssistedSetup tests the generation of the public key in push mode.
func TestCloudAssistedSetup(t *testing.T) {
	for _, literalParams := range rangeParam {
		for _, ts := range testSettings {

			if ts.T == 0 {
				ts.T = ts.N // N-out-of-N scenario
			}

			t.Run(fmt.Sprintf("NParty=%d/T=%d/logN=%d", ts.N, ts.T, literalParams.LogN), func(t *testing.T) {

				if ts.T != ts.N {
					t.Skip("T != N not yet supported in cloud-assisted setting")
				}

				var testConfig = node.LocalTestConfig{
					HelperNodes: 1, // the cloud
					LightNodes:  ts.N,
					Session: &node.SessionParameters{
						RLWEParams: literalParams,
						T:          ts.T,
					},
				}
				localTest := node.NewLocalTest(testConfig)

				params := localTest.Params

				setup := Description{
					Cpk:       true,
					GaloisEls: localTest.Params.GaloisElementsForRowInnerSum(),
					Rlk:       true,
					Delegated: false,
				}
				// define protocols to test
				protocolMap := GenerateProtocolMap(setup, localTest.LightNodes, ts.T, localTest.HelperNodes...)

				var err error

				clou := &cloud{Node: localTest.HelperNodes[0]}

				clou.Service, err = NewSetupService(clou.Node)
				if err != nil {
					t.Error(err)
				}

				sk := localTest.SkIdeal

				// initialise clients
				allNodes := []*Service{clou.Service}
				clients := make([]lightNode, ts.N)
				sessionNodes := localTest.SessionNodes()
				for i := range clients {
					clients[i].Node = sessionNodes[i]
					clients[i].Service, err = NewSetupService(clients[i].Node)
					if err != nil {
						t.Fatal(err)
					}
					allNodes = append(allNodes, clients[i].Service)
				}

				// loads the protocolMap at all nodes
				for _, n := range allNodes {
					sess, ok := n.GetSessionFromID("test-session")
					if !ok {
						t.Fatal("session should exist")
					}
					err = n.LoadProtocolMap(sess, protocolMap)
					if err != nil {
						t.Error(err)
					}
				}

				localTest.Start()

				// Start public key generation
				t.Run("FullSetup", func(t *testing.T) {

					g := new(errgroup.Group)

					// runs the cloud
					g.Go(func() error {
						// this takes care of populating the Peers map of the Service
						// (will be empty since the cloud has no full-n peer)
						clou.Service.Connect()
						// this should run the full n logic
						errExec := clou.Execute()
						if errExec != nil {
							errExec = fmt.Errorf("cloud (%s) error: %w", clou.ID(), errExec)
						}
						return errExec
					})

					// runs the clients
					for i := range clients {
						c := clients[i]
						g.Go(func() error {
							c.Service.Connect()
							errExec := c.Execute()
							if errExec != nil {
								errExec = fmt.Errorf("client (%s) error: %w", c.ID(), errExec)
							}
							return errExec
						})
					}

					err = g.Wait()
					if err != nil {
						t.Fatal(err)
					}

					// clou.PrintNetworkStats()

					for _, node := range allNodes {
						sess, ok := node.GetSessionFromID("test-session")
						if !ok {
							t.Fatal("session should exist")
						}
						checkKeyGenProt(t, sess, params, setup, sk, ts.N)
					}
				})
			})
		}
	}

}

func TestPeerToPeerSetup(t *testing.T) {

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
				}
				localTest := node.NewLocalTest(testConfig)

				params := localTest.Params
				peerIds := localTest.NodeIds()
				setup := Description{
					GaloisEls: localTest.Params.GaloisElementsForRowInnerSum(),
					Cpk:       true,
					Rlk:       true,
				}
				// define protocols to test
				protocolMap := GenerateProtocolMap(setup, localTest.Nodes, ts.T)

				var err error

				nodes := make(map[pkg.NodeID]*peer, ts.N)
				// initialise nodes, sessions and load protocols
				for _, n := range localTest.Nodes {
					n := &peer{Node: n}

					n.Service, err = NewSetupService(n.Node)
					if err != nil {
						t.Error(err)
					}

					sess, exists := n.GetSessionFromID("test-session")
					if !exists {
						t.Fatal("session should exists")
					}

					err = n.Service.LoadProtocolMap(sess, protocolMap)
					if err != nil {
						t.Fatal(err)
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
								node.Service.Connect()

								return node.Service.Execute()
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
						node.PrintNetworkStats()
						sess, _ := node.GetSessionFromID("test-session")
						checkKeyGenProt(t, sess, params, setup, localTest.SkIdeal, ts.N)
					}
				})
			})
		}
	}
}

// Based on the session information, check if the protocol was performed correctly.
func checkKeyGenProt(t *testing.T, sess *pkg.Session, params rlwe.Parameters, setup Description, sk *rlwe.SecretKey, nParties int) {

	if setup.Cpk {
		pk := sess.PublicKey
		if pk == nil {
			t.Fatalf("pk was not generated for node %s", sess.NodeID)
		}
		log2BoundPk := bits.Len64(uint64(nParties) * params.NoiseBound() * uint64(params.N()))
		require.True(t, rlwe.PublicKeyIsCorrect(pk, sk, params, log2BoundPk))
	}

	if !setup.Delegated {
		if setup.Rlk {
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

		for _, galEl := range setup.GaloisEls {
			rtk, isGen := sess.EvaluationKey.Rtks.Keys[galEl]
			if !isGen {
				t.Fatalf("rtk was not generated for node %s", sess.NodeID)
			}
			log2BoundRtk := bits.Len64(uint64(
				params.N() * len(rtk.Value) * len(rtk.Value[0]) *
					(params.N()*3*int(math.Floor(rlwe.DefaultSigma*6)) +
						2*3*int(math.Floor(rlwe.DefaultSigma*6)) + params.N()*3)))
			require.True(t, rlwe.RotationKeyIsCorrect(rtk, galEl, sk, params, log2BoundRtk), "rtk for galEl %d should be correct", galEl)
		}
	}

}
