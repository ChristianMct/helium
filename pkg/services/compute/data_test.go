package compute_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ldsec/helium/pkg"
	"github.com/ldsec/helium/pkg/node"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"golang.org/x/sync/errgroup"
)

func TestCloudDataTransfers(t *testing.T) {

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
					Session: &pkg.SessionParameters{
						RLWEParams: literalParams,
						T:          ts.T,
					},
					InsecureChannels: true,
				}

				localtest := node.NewLocalTest(testConfig)
				sessionID := pkg.SessionID("test-session")

				clou := cloud{Node: localtest.HelperNodes[0], Service: localtest.HelperNodes[0].GetComputeService()}
				clou.Session, _ = clou.GetSessionFromID(sessionID)

				params := localtest.Params
				bfvParams, _ := bfv.NewParameters(params, 65537)
				// initialise key generation
				kg := rlwe.NewKeyGenerator(params)
				sk := localtest.SkIdeal

				// initialise the cloud with given parameters and a session
				sess, ok := clou.GetSessionFromID(sessionID)
				if !ok {
					t.Fatal("session should exist")
				}
				// sess.PublicKey = kg.GenPublicKey(sk)
				if err := sess.SetCollectivePublicKey(kg.GenPublicKey(sk)); err != nil {
					t.Fatal(err)
				}
				// sess.Rlk = kg.GenRelinearizationKey(sk, 1)

				localtest.Start()

				// decryptor := bfv.NewDecryptor(bfvParams, sk)

				clients := make([]client, len(localtest.LightNodes))
				for i, node := range localtest.LightNodes {
					clients[i].Node = node
					clients[i].Service = node.GetComputeService()
					cpk, err := sess.GetCollectivePublicKey()
					if err != nil {
						t.Fatal(err)
					}
					clients[i].Encryptor = bfv.NewEncryptor(bfvParams, cpk)
				}

				t.Run("Store+Load", func(t *testing.T) {

					// t.Skip("skip")

					g := new(errgroup.Group)

					for i := range clients[:ts.N] {
						c := clients[i]
						ii := i

						g.Go(func() error {

							bfvCt := c.EncryptZeroNew(bfvParams.MaxLevel())

							ctID := fmt.Sprintf("ct[%d]", ii)
							msg := pkg.Ciphertext{Ciphertext: *bfvCt, CiphertextMetadata: pkg.CiphertextMetadata{ID: pkg.CiphertextID(ctID), Type: pkg.BFV}}

							ctx := context.TODO()
							rerr := c.SendCiphertext(ctx, clou.NodeID, msg)
							require.Nil(t, rerr, rerr)
							// require.Equal(t, ctID, rctID.CiphertextId)

							// req := &api.CiphertextRequest{Id: &api.CiphertextID{CiphertextId: ctID}}
							// resp, rerr := c.ComputeServiceClient.GetCiphertext(ctx, req)
							// require.Nil(t, rerr, rerr)

							// rct, errCt := pkg.NewCiphertextFromGRPC(resp)
							// require.Nil(t, errCt, rerr)
							// require.Equal(t, pkg.CiphertextID(ctID), rct.ID)
							// require.Equal(t, pkg.BFV, rct.Type)
							// require.True(t, rct.Ciphertext.Value[0].Equals(bfvCt.Value[0]) && rct.Ciphertext.Value[1].Equals(bfvCt.Value[1]))

							return nil
						})

					}

					err := g.Wait()
					if err != nil {
						t.Fatal(err)
					}

					<-time.After(time.Second)

				})
			})

		}
	}

}
