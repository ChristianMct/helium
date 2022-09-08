package compute

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"net"
	"testing"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/node"
	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/stretchr/testify/require"

	"github.com/tuneinsight/lattigo/v3/bfv"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

var rangeParam = []rlwe.ParametersLiteral{rlwe.TestPN12QP109, rlwe.TestPN13QP218, rlwe.TestPN14QP438, rlwe.TestPN15QP880}

type testSetting struct {
	N, T int
}

var testSettings = []testSetting{
	{N: 2},
}

//TestCloudAssistedCompute tests the generation of the public key in push mode
func TestCloudAssistedCompute(t *testing.T) {

	type cloud struct {
		*node.Node
		*ComputeService
	}

	type client struct {
		api.ComputeServiceClient
		bfv.Encryptor

		id   string
		addr string

		sk *rlwe.SecretKey
	}

	for _, literalParams := range rangeParam {
		for _, ts := range testSettings {

			if ts.T == 0 {
				ts.T = ts.N
			}

			t.Run(fmt.Sprintf("NParty=%d/T=%d/logN=%d", ts.N, ts.T, literalParams.LogN), func(t *testing.T) {

				if ts.T != ts.N {
					t.Skip("T != N not yet supported in cloud-assisted setting")
				}

				// initialise peers
				peers := make(map[pkg.NodeID]pkg.NodeAddress)
				peerIds := make([]pkg.NodeID, ts.N)
				for i := range peerIds {
					nid := pkg.NodeID(fmt.Sprint(i))
					peers[nid] = ""
					peerIds[i] = nid
				}

				sessParams := &node.SessionParameters{
					ID:         "test-session",
					RLWEParams: literalParams,
					Nodes:      peerIds,
					T:          ts.T,
					CRSKey:     []byte{'l', 'a', 't', 't', 'i', 'g', '0'},
				}

				params, _ := rlwe.NewParametersFromLiteral(literalParams)
				bfvParams, _ := bfv.NewParameters(params, 65537)

				var err error

				// initialise the cloud with given parameters and a session
				clou := cloud{Node: node.NewNode(node.NodeConfig{ID: "cloud", Address: "local", Peers: peers, SessionParameters: sessParams})}
				_, ok := clou.GetSessionFromID(pkg.SessionID(sessParams.ID))
				if !ok {
					t.Fatal("session should exist")
				}

				clou.ComputeService, err = NewComputeService(clou.Node)
				if err != nil {
					t.Error(err)
				}
				dialer := startTestService(clou.ComputeService)

				// initialise key generation
				kg := rlwe.NewKeyGenerator(params)
				ringQP := params.RingQP()
				sk := rlwe.NewSecretKey(params)

				// initialise clients
				clients := make([]client, ts.N)
				clientIDs := make([]pkg.NodeID, ts.N)
				for i := range clients {
					clients[i].id = fmt.Sprint(i)
					clients[i].addr = fmt.Sprint(i)
					clients[i].ComputeServiceClient = api.NewComputeServiceClient(getServiceClientConn(dialer))
					clients[i].sk = kg.GenSecretKey()
					ringQP.AddLvl(clients[i].sk.Value.Q.Level(), clients[i].sk.Value.P.Level(), clients[i].sk.Value, sk.Value, sk.Value)
					clientIDs[i] = pkg.NodeID(fmt.Sprint(i))
				}

				pk := kg.GenPublicKey(sk)

				for i := range clients {
					clients[i].Encryptor = bfv.NewEncryptor(bfvParams, pk)
				}

				// Start public key generation
				t.Run("Store+Load", func(t *testing.T) {

					g := new(errgroup.Group)

					// Allocate, generate and share (put) CKG Shares of each client
					for i := range clients[:ts.N] {
						c := clients[i]
						ii := i

						g.Go(func() error {

							bfvCt := c.EncryptZeroNew()

							ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("session_id", "test-session", "node_id", c.id))

							ctId := fmt.Sprintf("ct[%d]", ii)
							msg := pkg.Ciphertext{Ciphertext: *bfvCt.Ciphertext, CiphertextMetadata: pkg.CiphertextMetadata{ID: pkg.CiphertextID(ctId), Type: pkg.BFV}}.ToGRPC()

							rid, rerr := c.PutCiphertext(ctx, &msg)
							require.Nil(t, rerr)
							require.Equal(t, ctId, rid.CiphertextId)

							req := &api.CiphertextRequest{Id: &api.CiphertextID{CiphertextId: ctId}}
							resp, rerr := c.GetCiphertext(ctx, req)
							require.Nil(t, rerr)

							rct, err := pkg.NewCiphertextFromGRPC(resp)
							require.Nil(t, err)
							require.Equal(t, pkg.CiphertextID(ctId), rct.ID)
							require.Equal(t, pkg.BFV, rct.Type)
							require.True(t, rct.Ciphertext.Value[0].Equals(bfvCt.Value[0]) && rct.Ciphertext.Value[1].Equals(bfvCt.Value[1]))

							return nil
						})

					}

					err = g.Wait()
					if err != nil {
						t.Fatal(err)
					}

				})
			})
		}
	}

}

func startTestService(service interface{}) func(context.Context, string) (net.Conn, error) {
	srv := grpc.NewServer(grpc.MaxRecvMsgSize(1024*1024*1024), grpc.MaxSendMsgSize(1024*1024*1024))
	lis := bufconn.Listen(65 * 1024 * 1024)

	switch s := service.(type) {
	case *ComputeService:
		api.RegisterComputeServiceServer(srv, s)
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

func getServiceClientConn(dialer func(context.Context, string) (net.Conn, error)) *grpc.ClientConn {
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "", grpc.WithInsecure(), grpc.WithContextDialer(dialer), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(1024*1024*1024), grpc.MaxCallSendMsgSize(1024*1024*1024)))
	if err != nil {
		log.Fatal(err)
	}
	return conn
}

func GetSha256Hex(b []byte, err error) string {
	return fmt.Sprintf("%x", sha256.Sum256(b))
}
