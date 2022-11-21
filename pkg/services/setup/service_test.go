package setup

import (
	"context"
	"fmt"
	"math"
	"math/bits"
	"math/rand"
	"net"
	"testing"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/node"
	"github.com/ldsec/helium/pkg/protocols"
	pkg "github.com/ldsec/helium/pkg/session"

	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v3/rlwe"
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
	*SetupService

	dialer func(context.Context, string) (net.Conn, error)
}

type cloud struct {
	*node.Node
	*SetupService
}

type client struct {
	*node.Node
	*SetupService
}

// TestCloudAssistedSetup tests the generation of the public key in push mode
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
				peerIds := localTest.NodeIds()
				galEl := localTest.Params.GaloisElementForRowRotation()

				cloudID := localTest.HelperNodes[0].ID()
				// define protocols to test
				protocolMap := ProtocolMap{
					protocols.Descriptor{Type: api.ProtocolType_CKG, Aggregator: cloudID,
						Participants: getRandomClientSet(ts.T, peerIds[:ts.T])},
					protocols.Descriptor{Type: api.ProtocolType_RTG, Args: map[string]string{"GalEl": fmt.Sprint(galEl)},
						Aggregator: cloudID, Participants: getRandomClientSet(ts.T, peerIds[:ts.T])},
					protocols.Descriptor{Type: api.ProtocolType_RKG, Aggregator: cloudID,
						Participants: getRandomClientSet(ts.T, peerIds[:ts.T])},
				}

				var err error

				clou := cloud{Node: localTest.HelperNodes[0]}

				clou.SetupService, err = NewSetupService(clou.Node)
				if err != nil {
					t.Error(err)
				}

				sk := localTest.SkIdeal

				// initialise clients
				allNodes := []*SetupService{clou.SetupService}
				clients := make([]client, ts.N)
				sessionNodes := localTest.SessionNodes()
				for i := range clients {
					clients[i].Node = sessionNodes[i]
					clients[i].SetupService, err = NewSetupService(clients[i].Node)
					if err != nil {
						t.Fatal(err)
					}
					allNodes = append(allNodes, clients[i].SetupService)
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
						// this takes care of populating the Peers map of the SetupService
						// (will be empty since the cloud has no full-n peer)
						clou.SetupService.Connect()
						// this should run the full n logic
						err := clou.Execute()
						if err != nil {
							err = fmt.Errorf("cloud (%s) error: %w", clou.ID(), err)
						}
						return err
					})

					// runs the clients
					for i := range clients {
						c := clients[i]
						g.Go(func() error {
							c.SetupService.Connect()
							err := c.Execute()
							if err != nil {
								err = fmt.Errorf("client (%s) error: %w", c.ID(), err)
							}
							return err
						})
					}

					err = g.Wait()
					if err != nil {
						t.Fatal(err)
					}

					sess, ok := clou.GetSessionFromID("test-session")
					if !ok {
						t.Fatal("session should exist")
					}
					checkKeyGenProt(t, sess, params, galEl, sk, ts.N)
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
				galEl := localTest.Params.GaloisElementForRowRotation()

				// define protocols to test
				protocolMap := ProtocolMap{
					protocols.Descriptor{Type: api.ProtocolType_CKG, Aggregator: peerIds[0], Participants: getRandomClientSet(ts.T, peerIds)},
					protocols.Descriptor{Type: api.ProtocolType_RTG, Args: map[string]string{"GalEl": fmt.Sprint(galEl)}, Aggregator: peerIds[0], Participants: getRandomClientSet(ts.T, peerIds)},
					protocols.Descriptor{Type: api.ProtocolType_RKG, Aggregator: peerIds[0], Participants: getRandomClientSet(ts.T, peerIds)},
				}

				if ts.T < ts.N {
					protocolMap = append(ProtocolMap{
						protocols.Descriptor{Type: api.ProtocolType_SKG, Participants: peerIds},
					}, protocolMap...)
				}

				var err error

				nodes := make(map[pkg.NodeID]*peer, ts.N)
				// initialise nodes, sessions and load protocols
				for _, n := range localTest.Nodes {
					n := &peer{Node: n}

					n.SetupService, err = NewSetupService(n.Node)
					if err != nil {
						t.Error(err)
					}

					sess, exists := n.GetSessionFromID("test-session")
					if !exists {
						t.Fatal("session should exists")
					}

					err = n.SetupService.LoadProtocolMap(sess, protocolMap)
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
								node.SetupService.Connect()

								return node.SetupService.Execute()
							},
						)

					}
					err = g.Wait()
					if err != nil {
						t.Fatal(err)
					}

					node0 := nodes[peerIds[0]]

					sess, _ := node0.GetSessionFromID("test-session")

					if err != nil {
						t.Fatal(err)
					}

					checkKeyGenProt(t, sess, params, galEl, localTest.SkIdeal, ts.N)
				})
			})
		}
	}
}

func getRandomClientSet(t int, nodes []pkg.NodeID) []pkg.NodeID {
	cid := make([]pkg.NodeID, len(nodes))
	copy(cid, nodes)
	rand.Shuffle(len(cid), func(i, j int) {
		cid[i], cid[j] = cid[j], cid[i]
	})
	return cid[:t]
}

// Based on the session information, check if the protocol was performed correctly
func checkKeyGenProt(t *testing.T, sess *pkg.Session, params rlwe.Parameters, galEl uint64, sk *rlwe.SecretKey, N int) {
	pk := sess.PublicKey

	log2BoundPk := bits.Len64(uint64(N) * params.NoiseBound() * uint64(params.N()))
	require.True(t, rlwe.PublicKeyIsCorrect(pk, sk, params, log2BoundPk))

	rlk := sess.RelinearizationKey
	if rlk == nil {
		t.Fatal("rlk was not generated")
	}

	levelQ, levelP := params.QCount()-1, params.PCount()-1
	decompSize := params.DecompPw2(levelQ, levelP) * params.DecompRNS(levelQ, levelP)
	log2BoundRlk := bits.Len64(uint64(
		params.N() * decompSize * (params.N()*3*int(params.NoiseBound()) +
			2*3*int(params.NoiseBound()) + params.N()*3)))
	require.True(t, rlwe.RelinearizationKeyIsCorrect(rlk.Keys[0], sk, params, log2BoundRlk))

	rtk, isGen := sess.EvaluationKey.Rtks.Keys[galEl]
	if !isGen {
		t.Fatal("rtk was not generated")
	}

	log2BoundRtk := bits.Len64(uint64(
		params.N() * len(rtk.Value) * len(rtk.Value[0]) *
			(params.N()*3*int(math.Floor(rlwe.DefaultSigma*6)) +
				2*3*int(math.Floor(rlwe.DefaultSigma*6)) + params.N()*3)))
	require.True(t, rlwe.RotationKeyIsCorrect(rtk, galEl, sk, params, log2BoundRtk))
}
