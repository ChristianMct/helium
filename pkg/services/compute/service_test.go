package compute

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/node"
	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/stretchr/testify/require"

	"github.com/tuneinsight/lattigo/v3/bfv"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/metadata"
)

var rangeParam = []rlwe.ParametersLiteral{rlwe.TestPN12QP109, rlwe.TestPN13QP218, rlwe.TestPN14QP438, rlwe.TestPN15QP880}

type testSetting struct {
	N, T int
}

var testSettings = []testSetting{
	{N: 2},
}

var Prod = func(e bfv.Evaluator, in <-chan pkg.Operand, out chan<- pkg.Operand) error {

	lvl2 := make(chan *bfv.Ciphertext, 2)

	op0, op1 := <-in, <-in

	go func() {
		ev := e.ShallowCopy()
		res := ev.MulNew(op0.Ciphertext, op1.Ciphertext)
		ev.Relinearize(res, res)
		fmt.Println("computed lvl 1,1")
		lvl2 <- res
	}()

	op2, op3 := <-in, <-in

	go func() {
		ev := e.ShallowCopy()
		res := ev.MulNew(op2.Ciphertext, op3.Ciphertext)
		ev.Relinearize(res, res)
		fmt.Println("computed lvl 1,2")
		lvl2 <- res
	}()

	res1, res2 := <-lvl2, <-lvl2
	res := e.MulNew(res1, res2)
	e.Relinearize(res, res)
	fmt.Println("computed lvl 0")
	out <- pkg.Operand{OperandLabel: "/out-0", Ciphertext: res}
	close(out)
	return nil
}

var cDesc = CircuitDesc{CircuitName: "ComponentWiseProduct4P", CircuitID: "test-circuit-0", SessionID: "test-session"}

func TestPeerToPeerCompute(t *testing.T) {

	for _, literalParams := range rangeParam {
		for _, ts := range testSettings {

			if ts.T == 0 {
				ts.T = ts.N
			}

			t.Run(fmt.Sprintf("NParty=%d/T=%d/logN=%d", ts.N, ts.T, literalParams.LogN), func(t *testing.T) {

				var testConfig = node.LocalTestConfig{
					FullNodes: 4,
					Session: &node.SessionParameters{
						RLWEParams: literalParams,
						T:          ts.T,
					},
				}

				var cDef = pkg.LocalCircuitDef{
					Name:     "ComponentWiseProduct4P",
					Inputs:   []pkg.OperandLabel{"//full-0/in-0", "//full-1/in-0", "//full-2/in-0", "//full-3/in-0"},
					Outputs:  []pkg.OperandLabel{"/out-0"},
					Evaluate: Prod,
				}

				localtest := node.NewLocalTest(testConfig)

				params := localtest.Params
				bfvParams, _ := bfv.NewParameters(params, 65537)
				// initialise key generation
				kg := rlwe.NewKeyGenerator(params)
				sk := localtest.SkIdeal
				cpk := kg.GenPublicKey(sk)
				rlk := kg.GenRelinearizationKey(sk, 1)

				var err error
				nodes := make([]*ComputeService, len(localtest.Nodes))
				for i := range localtest.Nodes {
					nodes[i], err = NewComputeService(localtest.Nodes[i])
					if err != nil {
						t.Fatal(err)
					}
					sess, exists := nodes[i].GetSessionFromID("test-session")
					if !exists {
						t.Fatal("session should exist")
					}
					sess.PublicKey = cpk
					sess.Rlk = rlk
				}

				encryptor := bfv.NewEncryptor(bfvParams, cpk)
				decoder := bfv.NewEncoder(bfvParams)

				inputs := make(map[pkg.NodeID]pkg.Operand)
				for _, node := range nodes {
					pt := decoder.EncodeNew([]uint64{1, 1, 1, 1, 1, 1}, bfvParams.MaxLevel())
					ct := encryptor.EncryptNew(pt)
					inputs[node.ID()] = pkg.Operand{OperandLabel: pkg.OperandLabel(fmt.Sprintf("//%s/in-0", node.ID())), Ciphertext: ct}
				}

				localtest.Start()

				for _, node := range nodes {
					err := node.RegisterCircuit(cDef)
					if err != nil {
						t.Fatal(err)
					}
					err = node.LoadCircuit(cDesc)
					if err != nil {
						t.Fatal(err)
					}
				}

				g := new(errgroup.Group)
				for _, node := range nodes {
					node := node
					g.Go(func() error {
						node.Connect()
						out, err := node.Execute(cDesc, inputs[node.ID()])
						if err != nil {
							return fmt.Errorf("node %s: %s", node.ID(), err)
						}
						pt := bfv.NewDecryptor(bfvParams, sk).DecryptNew(out[0].Ciphertext)
						fmt.Println(bfv.NewEncoder(bfvParams).DecodeUintNew(pt)[:10])
						return nil
					})
				}

				err = g.Wait()
				if err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

//TestCloudAssistedCompute tests the generation of the public key in push mode
func TestCloudAssistedCompute(t *testing.T) {

	type client struct {
		*ComputeService
		api.ComputeServiceClient
		bfv.Encryptor
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
					FullNodes:  1,
					LightNodes: 4,
					Session: &node.SessionParameters{
						RLWEParams: literalParams,
						T:          ts.T,
					},
				}

				var cDef = pkg.LocalCircuitDef{
					Name:     "ComponentWiseProduct4P",
					Inputs:   []pkg.OperandLabel{"//light-0/in-0", "//light-1/in-0", "//light-2/in-0", "//light-3/in-0"},
					Outputs:  []pkg.OperandLabel{"/out-0"},
					Evaluate: Prod,
				}

				localtest := node.NewLocalTest(testConfig)

				clou, err := NewComputeService(localtest.FullNodes[0])
				if err != nil {
					t.Fatal(err)
				}
				nodes := []*ComputeService{clou}

				clients := make([]client, len(localtest.LightNodes))
				for i := range localtest.LightNodes {
					clients[i].ComputeService, err = NewComputeService(localtest.LightNodes[i])
					if err != nil {
						t.Fatal(err)
					}
					nodes = append(nodes, clients[i].ComputeService)
				}

				params := localtest.Params
				bfvParams, _ := bfv.NewParameters(params, 65537)

				// initialise the cloud with given parameters and a session
				sess, ok := clou.GetSessionFromID(pkg.SessionID("test-session"))
				if !ok {
					t.Fatal("session should exist")
				}

				localtest.Start()

				// initialise key generation
				kg := rlwe.NewKeyGenerator(params)
				sk := localtest.SkIdeal
				sess.PublicKey = kg.GenPublicKey(sk)
				sess.Rlk = kg.GenRelinearizationKey(sk, 1)

				decryptor := bfv.NewDecryptor(bfvParams, sk)
				decoder := bfv.NewEncoder(bfvParams)

				for i := range clients {
					clients[i].Connect()
					clients[i].Encryptor = bfv.NewEncryptor(bfvParams, sess.PublicKey)
					clients[i].ComputeServiceClient = clients[i].peers[clou.ID()]
				}

				t.Run("EvalCircuit", func(t *testing.T) {

					for _, node := range nodes {
						err := node.RegisterCircuit(cDef)
						if err != nil {
							t.Fatal(err)
						}
						err = node.LoadCircuit(cDesc)
						if err != nil {
							t.Fatal(err)
						}
					}

					g := new(errgroup.Group)

					var out []pkg.Operand

					g.Go(func() error {
						out, err = clou.Execute(cDesc)
						if err != nil {
							return fmt.Errorf("Node %s: %s", clou.ID(), err)
						}
						return nil
					})

					for _, client := range clients {
						client := client
						g.Go(func() error {
							pt := decoder.EncodeNew([]uint64{1, 1, 1, 1, 1, 1}, bfvParams.MaxLevel())
							ct := client.EncryptNew(pt)
							_, err := client.Execute(cDesc, pkg.Operand{OperandLabel: "in-0", Ciphertext: ct})
							if err != nil {
								return fmt.Errorf("client %s: %s", client.ID(), err)
							}
							return nil
						})
					}

					err := g.Wait()
					if err != nil {
						t.Fatal(err)
					}

					pt := decryptor.DecryptNew(out[0].Ciphertext)
					fmt.Println(decoder.DecodeUintNew(pt)[:10])

				})

				t.Run("Store+Load", func(t *testing.T) {

					t.Skip("skip")

					g := new(errgroup.Group)

					// Allocate, generate and share (put) CKG Shares of each client
					for i := range clients[:ts.N] {
						c := clients[i]
						ii := i

						g.Go(func() error {

							bfvCt := c.EncryptZeroNew()

							ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("session_id", "test-session", "node_id", string(c.ID())))

							ctId := fmt.Sprintf("ct[%d]", ii)
							msg := pkg.Ciphertext{Ciphertext: *bfvCt.Ciphertext, CiphertextMetadata: pkg.CiphertextMetadata{ID: pkg.CiphertextID(ctId), Type: pkg.BFV}}.ToGRPC()

							rid, rerr := c.ComputeServiceClient.PutCiphertext(ctx, msg)
							require.Nil(t, rerr, rerr)
							require.Equal(t, ctId, rid.CiphertextId)

							req := &api.CiphertextRequest{Id: &api.CiphertextID{CiphertextId: ctId}}
							resp, rerr := c.ComputeServiceClient.GetCiphertext(ctx, req)
							require.Nil(t, rerr, rerr)

							rct, err := pkg.NewCiphertextFromGRPC(resp)
							require.Nil(t, err, rerr)
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

func GetSha256Hex(b []byte, err error) string {
	return fmt.Sprintf("%x", sha256.Sum256(b))
}
