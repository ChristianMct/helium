package compute

import (
	"context"
	"fmt"
	"testing"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/node"
	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/metadata"
)

func TestCloudDataTransfers(t *testing.T) {

	type client struct {
		*Service
		api.ComputeServiceClient
		rlwe.Encryptor
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

				var testConfig = node.LocalTestConfig{
					HelperNodes: 1,
					LightNodes:  4,
					Session: &node.SessionParameters{
						RLWEParams: literalParams,
						T:          ts.T,
					},
				}

				localtest := node.NewLocalTest(testConfig)

				clou, err := NewComputeService(localtest.HelperNodes[0])
				if err != nil {
					t.Fatal(err)
				}
				nodes := []*Service{clou}

				clients := make([]client, len(localtest.LightNodes))
				for i := range localtest.LightNodes {
					clients[i].Service, err = NewComputeService(localtest.LightNodes[i])
					if err != nil {
						t.Fatal(err)
					}
					nodes = append(nodes, clients[i].Service)
				}

				params := localtest.Params
				bfvParams, _ := bfv.NewParameters(params, 65537)
				// initialise key generation
				kg := rlwe.NewKeyGenerator(params)
				sk := localtest.SkIdeal

				// initialise the cloud with given parameters and a session
				sess, ok := clou.GetSessionFromID(pkg.SessionID("test-session"))
				if !ok {
					t.Fatal("session should exist")
				}
				sess.PublicKey = kg.GenPublicKey(sk)
				sess.Rlk = kg.GenRelinearizationKey(sk, 1)

				localtest.Start()

				// decryptor := bfv.NewDecryptor(bfvParams, sk)

				for i := range clients {
					clients[i].Connect()
					clients[i].Encryptor = bfv.NewEncryptor(bfvParams, sess.PublicKey)
					clients[i].ComputeServiceClient = clients[i].peers[clou.ID()]
				}

				t.Run("Store+Load", func(t *testing.T) {

					t.Skip("skip")

					g := new(errgroup.Group)

					// Allocate, generate and share (put) CKG Shares of each client
					for i := range clients[:ts.N] {
						c := clients[i]
						ii := i

						g.Go(func() error {

							bfvCt := c.EncryptZeroNew(bfvParams.MaxLevel())

							ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("session_id", "test-session", "sender_id", string(c.ID())))

							ctID := fmt.Sprintf("ct[%d]", ii)
							msg := pkg.Ciphertext{Ciphertext: *bfvCt, CiphertextMetadata: pkg.CiphertextMetadata{ID: pkg.CiphertextID(ctID), Type: pkg.BFV}}.ToGRPC()

							rctID, rerr := c.ComputeServiceClient.PutCiphertext(ctx, msg)
							require.Nil(t, rerr, rerr)
							require.Equal(t, ctID, rctID.CiphertextId)

							req := &api.CiphertextRequest{Id: &api.CiphertextID{CiphertextId: ctID}}
							resp, rerr := c.ComputeServiceClient.GetCiphertext(ctx, req)
							require.Nil(t, rerr, rerr)

							rct, errCt := pkg.NewCiphertextFromGRPC(resp)
							require.Nil(t, errCt, rerr)
							require.Equal(t, pkg.CiphertextID(ctID), rct.ID)
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
