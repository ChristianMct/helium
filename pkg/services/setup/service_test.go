package setup

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"math"
	"math/bits"
	"math/rand"
	"net"
	"testing"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/node"
	pkg "github.com/ldsec/helium/pkg/session"

	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v3/drlwe"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"github.com/tuneinsight/lattigo/v3/utils"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
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
		//api.SetupServiceClient
		*SetupService

		sk *rlwe.SecretKey // ultimately remove this @adrian
	}

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
					ProtocolDescriptor{Type: api.ProtocolType_CKG, Aggregator: cloudID,
						Participants: getRandomClientSet(ts.T, peerIds[:ts.T])},
					ProtocolDescriptor{Type: api.ProtocolType_RTG, Args: map[string]string{"GalEl": fmt.Sprint(galEl)},
						Aggregator: cloudID, Participants: getRandomClientSet(ts.T, peerIds[:ts.T])},
					ProtocolDescriptor{Type: api.ProtocolType_RKG, Aggregator: cloudID,
						Participants: getRandomClientSet(ts.T, peerIds[:ts.T])},
				}

				var err error

				//fmt.Printf("light nodes: %v\n", localTest.LightNodes[0])
				//fmt.Printf("helper node: %v\n", localTest.HelperNodes[0])

				clou := cloud{Node: localTest.HelperNodes[0]}
				//fmt.Printf("clou: %v\n", clou.Node.ID())

				sess, ok := clou.GetSessionFromID("test-session")
				if !ok {
					t.Fatal("session should exist")
				}

				clou.SetupService, err = NewSetupService(clou.Node)
				if err != nil {
					t.Error(err)
				}
				dialer := startTestService(clou.SetupService)

				// initialise key generation
				kg := rlwe.NewKeyGenerator(params)
				ringQP := params.RingQP()
				sk := rlwe.NewSecretKey(params)

				// initialise clients

				clients := make([]client, ts.N)
				sessionNodes := localTest.SessionNodes()
				clientIDs := peerIds[:ts.N]
				for i := range clients {
					clients[i].Node = sessionNodes[i]
					//clients[i].SetupServiceClient = api.NewSetupServiceClient(getServiceClientConn(dialer))
					clients[i].SetupService, err = NewSetupService(clients[i].Node)
					if err != nil {
						t.Fatal(err)
					}
					// not sure about this - the light nodes need to have the cloud as a peer
					// but I think it leads to
					clients[i].SetupService.peers = map[pkg.NodeID]api.SetupServiceClient{
						cloudID: api.NewSetupServiceClient(getServiceClientConn(dialer)),
					}

					// idea: first get rid of the need to generate keys, let node CreateNewSession handle that. @adrian
					clients[i].sk = kg.GenSecretKey()

					// once that works, can replace .sk with the value from the session.
					//sess_light, exists := clients[i].GetSessionFromID("test-session")
					//if !exists {
					//	t.Fatal("session should exists")
					//}
					//sk = sess_light.GetSecretKey()

					ringQP.AddLvl(clients[i].sk.Value.Q.Level(), clients[i].sk.Value.P.Level(), clients[i].sk.Value, sk.Value, sk.Value)
				}

				err = clou.SetupService.LoadProtocolMap(sess, protocolMap)
				if err != nil {
					t.Error(err)
				}

				// Start public key generation
				t.Run("FullSetup", func(t *testing.T) {
					crs, err := utils.NewKeyedPRNG([]byte{'l', 'a', 't', 't', 'i', 'g', '0'})
					if err != nil {
						t.Fatal(err)
					}
					ckgProt := drlwe.NewCKGProtocol(params)
					rkgProt := drlwe.NewRKGProtocol(params)
					rtgProt := drlwe.NewRTGProtocol(params)
					ckgCRP := ckgProt.SampleCRP(crs)
					rtgCRP := rtgProt.SampleCRP(crs)
					rkgCRP := rkgProt.SampleCRP(crs)

					g := new(errgroup.Group)

					// Allocate, generate and share (put) CKG Shares of each client
					for i := range clients[:ts.N] {
						c := clients[i]

						g.Go(func() error {

							ctx := metadata.NewOutgoingContext(context.Background(),
								metadata.Pairs("session_id", "test-session", "node_id", string(c.Node.ID())))

							// Lunches a series of request to check for protocolMap completion
							reqs := new(errgroup.Group)
							for _, proto := range protocolMap {
								truep := true
								participants := make([]*api.NodeID, len(proto.Participants))
								for i, nodeId := range proto.Participants {
									participants[i] = &api.NodeID{NodeId: string(nodeId)}
								}
								sReq := &api.ShareRequest{ProtocolID: &api.ProtocolID{
									ProtocolID: (&api.ProtocolDescriptor{Type: proto.Type}).String()},
									AggregateFor: participants, NoData: &truep}
								if proto.Type == api.ProtocolType_RKG {
									two := uint64(2)
									sReq.Round = &two
								}
								reqs.Go(func() error {
									_, err := c.GetShare(ctx, sReq)
									//fmt.Println("ret", sReq.ProtocolID, "for", c.addr)
									if err != nil {
										return err
									}
									return nil
								})
							}

							ckgProt := drlwe.NewCKGProtocol(params)
							rkgProt := drlwe.NewRKGProtocol(params)
							rtgProt := drlwe.NewRTGProtocol(params)

							// CKG Protocol

							ckgShare := ckgProt.AllocateShare()
							ckgProt.GenShare(c.sk, ckgCRP, ckgShare)
							ckgShareb, err := ckgShare.MarshalBinary()
							if err != nil {
								return err
							}
							protoID := &api.ProtocolID{ProtocolID: (&api.ProtocolDescriptor{Type: api.ProtocolType_CKG}).String()}
							_, err = c.PutShare(ctx, &api.Share{ProtocolID: protoID, Share: ckgShareb})
							if err != nil {
								return err
							}

							// RTG Protocol

							rtgShare := rtgProt.AllocateShare()
							rtgProt.GenShare(c.sk, galEl, rtgCRP, rtgShare)
							rtgShareb, err := rtgShare.MarshalBinary()
							if err != nil {
								return err
							}
							protoID = &api.ProtocolID{ProtocolID: (&api.ProtocolDescriptor{Type: api.ProtocolType_RTG}).String()}
							_, err = c.PutShare(ctx, &api.Share{ProtocolID: protoID, Share: rtgShareb})
							if err != nil {
								return err
							}

							// RKG Protocol

							rkgEphSK, rkgShareR1, rkgShareR2 := rkgProt.AllocateShare()
							rkgProt.GenShareRoundOne(c.sk, rkgCRP, rkgEphSK, rkgShareR1)
							rkgShareb, err := rkgShareR1.MarshalBinary()
							if err != nil {
								return err
							}
							protoID = &api.ProtocolID{ProtocolID: (&api.ProtocolDescriptor{Type: api.ProtocolType_RKG}).String()}
							var one uint64 = 1
							_, err = c.PutShare(ctx, &api.Share{ProtocolID: protoID, Share: rkgShareb, Round: &one})
							if err != nil {
								return err
							}
							participants := make([]*api.NodeID, len(clientIDs))
							for i, nodeId := range clientIDs {
								participants[i] = &api.NodeID{NodeId: string(nodeId)}
							}
							aggShareR1m, err := c.GetShare(ctx, &api.ShareRequest{ProtocolID: protoID, Round: &one, AggregateFor: participants})
							if err != nil {
								return err
							}
							var aggShareR1 drlwe.RKGShare
							err = aggShareR1.UnmarshalBinary(aggShareR1m.Share)
							if err != nil {
								return err
							}
							rkgProt.GenShareRoundTwo(rkgEphSK, c.sk, &aggShareR1, rkgShareR2)
							rkgShareb, err = rkgShareR2.MarshalBinary()
							if err != nil {
								return err
							}
							var two uint64 = 2
							_, err = c.PutShare(ctx, &api.Share{ProtocolID: protoID, Round: &two, Share: rkgShareb})
							if err != nil {
								return err
							}

							return reqs.Wait()
						})

					}

					err = g.Wait()
					if err != nil {
						t.Fatal(err)
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

func startTestService(service interface{}) func(context.Context, string) (net.Conn, error) {
	srv := grpc.NewServer(grpc.MaxRecvMsgSize(1024*1024*1024), grpc.MaxSendMsgSize(1024*1024*1024))
	lis := bufconn.Listen(65 * 1024 * 1024)

	switch s := service.(type) {
	case *SetupService:
		api.RegisterSetupServiceServer(srv, s)
	default:
		log.Fatalf("invalid service type provided: %T", s)
	}

	go func() {
		if err := srv.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	return func(context.Context, string) (net.Conn, error) { return lis.Dial() }
}

func getRandomClientSet(t int, nodes []pkg.NodeID) []pkg.NodeID {
	cid := make([]pkg.NodeID, len(nodes))
	copy(cid, nodes)
	rand.Shuffle(len(cid), func(i, j int) {
		cid[i], cid[j] = cid[j], cid[i]
	})
	return cid[:t]
}

func getServiceClientConn(dialer func(context.Context, string) (net.Conn, error)) *grpc.ClientConn {
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "", grpc.WithInsecure(), grpc.WithContextDialer(dialer), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(1024*1024*1024), grpc.MaxCallSendMsgSize(1024*1024*1024)))
	if err != nil {
		log.Fatal(err)
	}
	return conn
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
