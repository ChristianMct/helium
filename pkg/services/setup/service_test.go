package setup

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math"
	"math/bits"
	"math/rand"
	"net"
	"testing"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/node"
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

// TestCloudAssistedSetup tests the generation of the public key in push mode
func TestCloudAssistedSetup(t *testing.T) { // TODO: refactor to use light nodes

	type cloud struct {
		*node.Node
		*SetupService
	}

	type client struct {
		*node.Node
		*SetupService
	}

	// todo: remove after testing
	for _, literalParams := range rangeParam[:1] {
		for _, ts := range testSettings[:1] {

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
					ProtocolDescriptor{Type: api.ProtocolType_CKG, Aggregator: cloudID,
						Participants: getRandomClientSet(ts.T, peerIds[:ts.T])},
					ProtocolDescriptor{Type: api.ProtocolType_RTG, Args: map[string]string{"GalEl": fmt.Sprint(galEl)},
						Aggregator: cloudID, Participants: getRandomClientSet(ts.T, peerIds[:ts.T])},
					// ProtocolDescriptor{Type: api.ProtocolType_RKG, Aggregator: cloudID,					This one is a bit more tricky because it has two rounds.
					//	Participants: getRandomClientSet(ts.T, peerIds[:ts.T])},							Have a first go without it
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

				// loads the protocolmap at all nodes
				for _, node := range allNodes {
					sess, ok := node.GetSessionFromID("test-session")
					if !ok {
						t.Fatal("session should exist")
					}
					err = node.LoadProtocolMap(sess, protocolMap)
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
						// TODO: cloud has light-1 and light-0 as its peers actually...
						clou.SetupService.Connect() // this takes care of populating the Peers map of the SetupService (will be empty since the cloud has no full-node peer)
						err := clou.Execute()       // this should run the full node logic (waiting for aggregating the shares, already implemented in current code)
						if err != nil {
							err = fmt.Errorf("cloud error: %s", err)
						}
						return err
					})

					// runs the clients
					for i := range clients {
						c := clients[i]
						g.Go(func() error {
							c.SetupService.Connect() // this takes care of populating the Peers map of the SetupService (should contain the cloud as the only full-node peer)
							err := c.Execute()       // this should run the light-node logic (figure out what protocol need to run and send the corresponding shares to the cloud, not yet implemented)
							if err != nil {
								err = fmt.Errorf("client error: %s", err)
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

	type peer struct {
		*node.Node
		*SetupService

		dialer func(context.Context, string) (net.Conn, error)
	}

	for _, literalParams := range rangeParam {
		for _, ts := range testSettings {

			if ts.T == 0 {
				ts.T = ts.N
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
				localtest := node.NewLocalTest(testConfig)

				params := localtest.Params
				peerIds := localtest.NodeIds()
				galEl := localtest.Params.GaloisElementForRowRotation()

				// define protocols to test
				protocolMap := ProtocolMap{
					ProtocolDescriptor{Type: api.ProtocolType_CKG, Aggregator: peerIds[0], Participants: getRandomClientSet(ts.T, peerIds)},
					ProtocolDescriptor{Type: api.ProtocolType_RTG, Args: map[string]string{"GalEl": fmt.Sprint(galEl)}, Aggregator: peerIds[0], Participants: getRandomClientSet(ts.T, peerIds)},
					ProtocolDescriptor{Type: api.ProtocolType_RKG, Aggregator: peerIds[0], Participants: getRandomClientSet(ts.T, peerIds)},
				}

				if ts.T < ts.N {
					protocolMap = append(ProtocolMap{
						ProtocolDescriptor{Type: api.ProtocolType_SKG, Participants: peerIds},
					}, protocolMap...)
				}

				var err error

				nodes := make(map[pkg.NodeID]*peer, ts.N)
				// initialise nodes, sessions and load protocols
				for _, node := range localtest.Nodes {
					n := &peer{Node: node}

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

					nodes[node.ID()] = n
				}

				localtest.Start()

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

					//pk := sess.PublicKey
					// todo: not sure exactly what error is checked here?
					if err != nil {
						t.Fatal(err)
					}

					checkKeyGenProt(t, sess, params, galEl, localtest.SkIdeal, ts.N)
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

func GetSha256Hex(b []byte, err error) string {
	return fmt.Sprintf("%x", sha256.Sum256(b))
}
