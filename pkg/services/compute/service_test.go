package compute_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/ldsec/helium/pkg/circuits"
	"github.com/ldsec/helium/pkg/node"
	"github.com/ldsec/helium/pkg/pkg"
	. "github.com/ldsec/helium/pkg/services/compute"
	"github.com/ldsec/helium/pkg/services/setup"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/stretchr/testify/require"

	"github.com/tuneinsight/lattigo/v4/bgv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"golang.org/x/sync/errgroup"
)

var testPN13QP218 = bgv.ParametersLiteral{
	LogN: 13,
	Q:    []uint64{0x3fffffffef8001, 0x4000000011c001, 0x40000000120001}, // 54 + 54 + 54 bits
	P:    []uint64{0x7ffffffffb4001},                                     // 55 bits
	T:    65537,                                                          // TODO should not have to specify this in bgv.NewParameters
}

var rangeParam = []bgv.ParametersLiteral{ /*rlwe.TestPN12QP109 , */ testPN13QP218 /* rlwe.TestPN14QP438, rlwe.TestPN15QP880 */}

type testSetting struct {
	N, T int
}

var testSettings = []testSetting{
	{N: 4},
	{N: 4, T: 3},
}

type peer struct {
	*node.Node
	*Service
	*pkg.Session
}

type cloud struct {
	*node.Node
	*Service
	*pkg.Session
}

type lightNode struct {
	*node.Node
	*Service
	*pkg.Session
}

type client struct {
	lightNode
	*bgv.Encoder
	*rlwe.Encryptor
}

func TestCloudEvalCircuit(t *testing.T) {

	for label, cDef := range node.TestCircuits {
		if err := RegisterCircuit(label, cDef); err != nil {
			t.Log(err)
		}
	}

	for _, literalParams := range rangeParam {
		for _, ts := range testSettings {

			if ts.T == 0 {
				ts.T = ts.N
			}

			t.Run(fmt.Sprintf("NParty=%d/T=%d/logN=%d", ts.N, ts.T, literalParams.LogN), func(t *testing.T) {

				var testConfig = node.LocalTestConfig{
					HelperNodes: 1,
					LightNodes:  4,
					Session: &pkg.SessionParameters{
						RLWEParams: literalParams,
						T:          ts.T,
					},
					SimSetup: &setup.Description{Cpk: []pkg.NodeID{}, Rlk: []pkg.NodeID{}},
				}

				localtest := node.NewLocalTest(testConfig)
				sessionID := pkg.SessionID("test-session")

				clou := cloud{Node: localtest.HelperNodes[0], Service: localtest.HelperNodes[0].GetComputeService()}
				clou.Session, _ = localtest.HelperNodes[0].GetSessionFromID(sessionID)

				nodes := []*Service{clou.Service}

				clients := make([]client, len(localtest.LightNodes))
				for i, node := range localtest.LightNodes {
					clients[i].Node = node
					clients[i].Service = node.GetComputeService()
					clients[i].Session, _ = node.GetSessionFromID(sessionID)
					nodes = append(nodes, clients[i].Service)
				}

				params := localtest.Params
				bgvParams := params

				localtest.Start()

				decoder := bgv.NewEncoder(bgvParams)

				var cSigns = []circuits.Signature{
					{CircuitName: "mul4-dec", CircuitID: pkg.CircuitID("test-circuit-0")},
					{CircuitName: "mul4-dec", CircuitID: pkg.CircuitID("test-circuit-1")},
					{CircuitName: "mul4-dec", CircuitID: pkg.CircuitID("test-circuit-2")},
					{CircuitName: "mul4-dec", CircuitID: pkg.CircuitID("test-circuit-3")},
					{CircuitName: "mul4-dec", CircuitID: pkg.CircuitID("test-circuit-4")},
				}

				var err error
				cDescs := make([]*CircuitDescription, len(cSigns))
				for i, cSign := range cSigns {
					c := node.TestCircuits[cSign.CircuitName]
					cDescs[i], err = ParseCircuit(c, cSign.CircuitID, bgvParams, nil)
					if err != nil {
						t.Fatal(err)
					}
				}

				sigs := make(chan circuits.Signature, len(cSigns))
				for _, sig := range cSigns {
					sigs <- sig
				}
				close(sigs)

				ctx := pkg.NewContext(&sessionID, nil)

				g := new(errgroup.Group)

				outs := make(chan CircuitOutput)
				g.Go(func() error {
					err := clou.Execute(ctx, sigs, NoInput, outs)
					if err != nil {
						return fmt.Errorf("Node %s: %w", clou.Node.ID(), err)
					}
					return nil
				})

				for i, client := range clients {
					client := client
					i := i
					g.Go(func() error {

						if i == 0 {
							<-time.After(time.Second)
						}

						var ip InputProvider = func(ctx context.Context, inLabel pkg.OperandLabel) (*rlwe.Plaintext, error) {
							encoder := decoder.ShallowCopy()
							data := []uint64{1, 1, 1, 1, 1, 1}
							data[i] = uint64(i + 1)
							pt := bgv.NewPlaintext(params, params.MaxLevelQ())
							err := encoder.Encode(data, pt)
							if err != nil {
								return nil, err
							}
							return pt, nil
						}

						outLabels := utils.NewEmptySet[pkg.OperandLabel]()
						for _, cDesc := range cDescs {
							outLabels.AddAll(cDesc.OutputsFor[client.NodeID])
						}
						outChan := make(chan CircuitOutput, len(outLabels))
						errExec := client.Execute(ctx, nil, ip, outChan)
						if errExec != nil {
							return fmt.Errorf("client %s: %w", client.Node.ID(), errExec)
						}

						if len(outLabels) > 0 {

							for out := range outChan {
								if out.Error != nil {
									t.Errorf("unexpected error in output: %s", out.Error)
								}

								if !outLabels.Contains(out.OperandLabel) {
									t.Errorf("unexpected operand output: %v", out.OperandLabel)
								}
								outLabels.Remove(out.OperandLabel)

								outs <- out
							}

							if len(outLabels) != 0 {
								t.Errorf("expected outputs where not received: %v", outLabels)
							}

						}
						client.Node.Logf("is done")
						return nil
					})
				}

				for out := range outs {
					ptdec := out.Pt
					res := make([]uint64, bgvParams.PlaintextSlots())
					err = decoder.Decode(ptdec, res)
					if err != nil {
						t.Fatal(err)
					}
					require.Equal(t, []uint64{1, 2, 3, 4, 1, 1}, res[:6])
				}

				if err := g.Wait(); err != nil {
					t.Fatal(err)
				}
			})

		}
	}

}

// // TestCloudPCKS runs the compute phase and executes the psi-2-PCKS circuit to test the sending of the external receiver public key.
// func TestCloudPCKS(t *testing.T) {

// 	for label, cDef := range TestCircuits {
// 		if err := RegisterCircuit(label, cDef); err != nil {
// 			t.Log(err)
// 		}
// 	}

// 	for _, literalParams := range rangeParam {
// 		for _, ts := range testSettings {

// 			if ts.T == 0 {
// 				ts.T = ts.N
// 			}

// 			t.Run(fmt.Sprintf("NParty=%d/T=%d/logN=%d", ts.N, ts.T, literalParams.LogN), func(t *testing.T) {

// 				var testConfig = node.LocalTestConfig{
// 					HelperNodes:   1,
// 					LightNodes:    2,
// 					ExternalNodes: 1,
// 					Session: &pkg.SessionParameters{
// 						RLWEParams: literalParams,
// 						T:          ts.T,
// 					},
// 					SimSetup: &setup.Description{Cpk: []pkg.NodeID{}, Rlk: []pkg.NodeID{}},
// 				}

// 				localtest := node.NewLocalTest(testConfig)
// 				sessionID := pkg.SessionID("test-session")

// 				clou := cloud{Node: localtest.HelperNodes[0], Service: localtest.HelperNodes[0].GetComputeService()}
// 				clou.Session, _ = localtest.HelperNodes[0].GetSessionFromID(sessionID)

// 				external_0 := localtest.ExternalNodes[0]
// 				external_0Sess, _ := external_0.GetSessionFromID(sessionID)

// 				nodes := []*Service{clou.Service, external_0.GetComputeService()}

// 				clients := make([]client, len(localtest.LightNodes))
// 				for i, node := range localtest.LightNodes {
// 					clients[i].Node = node
// 					clients[i].Service = node.GetComputeService()
// 					clients[i].Session, _ = node.GetSessionFromID(sessionID)
// 					nodes = append(nodes, clients[i].Service)
// 				}

// 				params := localtest.Params
// 				bgvParams, _ := bgv.NewParameters(params, 65537)

// 				localtest.Start()

// 				encoder := bgv.NewEncoder(bgvParams)

// 				recPk, err := external_0Sess.GetPublicKey()
// 				if err != nil {
// 					t.Fatal(err)
// 				}

// 				if err := clou.Session.SetOutputPkForNode("external-0", recPk); err != nil {
// 					t.Fatal(err)
// 				}
// 				if err := external_0Sess.SetOutputPkForNode("external-0", recPk); err != nil {
// 					t.Fatal(err)
// 				}
// 				for i := range clients {
// 					cliSess, _ := clients[i].GetSessionFromID(sessionID)
// 					if err = cliSess.SetOutputPkForNode("external-0", recPk); err != nil {
// 						t.Fatal(err)
// 					}
// 				}

// 				var cSigns = []circuits.Signature{
// 					circuits.Signature{CircuitName: "psi-2PCKS", CircuitID: pkg.CircuitID("test-circuit-0")},
// 					circuits.Signature{CircuitName: "psi-2PCKS", CircuitID: pkg.CircuitID("test-circuit-1")},
// 					circuits.Signature{CircuitName: "psi-2PCKS", CircuitID: pkg.CircuitID("test-circuit-2")},
// 				}

// 				cDescs := make([]*CircuitDescription, len(cSigns))
// 				for i, cSign := range cSigns {
// 					c := TestCircuits[cSign.CircuitName]
// 					cDescs[i], err = ParseCircuit(c, cSign.CircuitID, bgvParams, nil)
// 					if err != nil {
// 						t.Fatal(err)
// 					}
// 				}

// 				sigs := make(chan circuits.Signature, len(cSigns))
// 				for _, sig := range cSigns {
// 					sigs <- sig
// 				}
// 				close(sigs)

// 				ctx := pkg.NewContext(&sessionID, nil)
// 				g := new(errgroup.Group)

// 				// execute cloud
// 				g.Go(func() error {
// 					err := clou.Execute(ctx, sigs, NoInput, nil)
// 					if err != nil {
// 						return fmt.Errorf("Node %s: %w", clou.Node.ID(), err)
// 					}
// 					return nil
// 				})

// 				// execute clients
// 				for i, client := range clients {
// 					client := client
// 					i := i
// 					g.Go(func() error {
// 						encoder := encoder.ShallowCopy()
// 						ip := func(ctx context.Context, inLabel pkg.OperandLabel) (*rlwe.Plaintext, error) {
// 							data := make([]uint64, 6)
// 							data[i] = 1
// 							data[i+1] = 1
// 							pt := bgv.NewPlaintext(params, params.MaxLevelQ())
// 							encoder.Encode(data, pt)
// 							// ct, err := client.Encryptor.EncryptNew(pt)
// 							// if err != nil {
// 							// 	t.Fatal(err)
// 							// }
// 							return pt, nil
// 						}

// 						errExec := client.Execute(ctx, nil, ip, nil)
// 						if errExec != nil {
// 							return fmt.Errorf("client %s: %w", client.Node.ID(), errExec)
// 						}

// 						return nil
// 					})
// 				}

// 				// execute external receiver
// 				g.Go(func() error {
// 					outLabels := utils.NewEmptySet[pkg.OperandLabel]()
// 					for _, cDesc := range cDescs {
// 						outLabels.AddAll(cDesc.OutputsFor[external_0.ID()])
// 					}
// 					outChan := make(chan CircuitOutput, len(outLabels))
// 					err := external_0.GetComputeService().Execute(ctx, nil, NoInput, outChan)
// 					if err != nil {
// 						return fmt.Errorf("Node %s: %w", external_0.ID(), err)
// 					}

// 					// outputSk, err := external_0Sess.GetSecretKey()
// 					// if err != nil {
// 					// 	return fmt.Errorf("could not read receiver's (%s) private key: %w\n", external_0.ID(), err)

// 					// }
// 					// decryptor, err := bgv.NewDecryptor(bgvParams, outputSk)
// 					// if err != nil {
// 					// 	t.Fatal(err)
// 					// }

// 					for out := range outChan {
// 						ptdec := out.Pt
// 						res := make([]uint64, bgvParams.PlaintextSlots())
// 						encoder.Decode(ptdec, res)
// 						require.Equal(t, []uint64{0, 1, 0, 0, 0, 0}, res[:6])
// 					}
// 					return nil
// 				})

// 				if err := g.Wait(); err != nil {
// 					t.Fatal(err)
// 				}
// 			})

// 		}
// 	}
// }

// func TestPeerEvalCircuit(t *testing.T) {

// 	t.Skip("skipped: current version focuses on the cloud-based model")

// 	for label, cDef := range TestCircuits {
// 		if err := RegisterCircuit(label, cDef); err != nil {
// 			t.Log(err)
// 		}
// 	}

// 	for _, literalParams := range rangeParam {
// 		for _, ts := range testSettings {

// 			if ts.T == 0 {
// 				ts.T = ts.N
// 			}

// 			t.Run(fmt.Sprintf("NParty=%d/T=%d/logN=%d", ts.N, ts.T, literalParams.LogN), func(t *testing.T) {

// 				var testConfig = node.LocalTestConfig{
// 					FullNodes: 4,
// 					Session: &pkg.SessionParameters{
// 						RLWEParams: literalParams,
// 						T:          ts.T,
// 					},
// 					InsecureChannels: true,
// 				}

// 				var cDesc = Signature{CircuitName: "Mul4CKS"}

// 				sessionID := pkg.SessionID("test-session")
// 				cLabel := pkg.CircuitID("test-circuit-0")

// 				localtest := node.NewLocalTest(testConfig)

// 				params := localtest.Params
// 				bgvParams, _ := bgv.NewParameters(params, 65537)
// 				// initialise key generation
// 				kg := rlwe.NewKeyGenerator(params)
// 				sk := localtest.SkIdeal
// 				cpk := kg.GenPublicKey(sk)
// 				rlk := kg.GenRelinearizationKey(sk, 1)

// 				// recSk, recPk := kg.GenKeyPair()

// 				var err error
// 				nodes := make([]peer, len(localtest.Nodes))
// 				for i, node := range localtest.Nodes {
// 					nodes[i].Node = node
// 					nodes[i].Service = node.GetComputeService()
// 					nodes[i].Session, _ = nodes[i].GetSessionFromID(sessionID)
// 					if err = nodes[i].Session.SetCollectivePublicKey(cpk); err != nil {
// 						t.Fatal(err)
// 					}
// 					if err = nodes[i].Session.SetRelinearizationKey(rlk); err != nil {
// 						t.Fatal(err)
// 					}
// 				}

// 				encryptor := bgv.NewEncryptor(bgvParams, cpk)
// 				decoder := bgv.NewEncoder(bgvParams)

// 				inputs := make(map[pkg.NodeID]pkg.Operand)
// 				for i, node := range nodes {
// 					data := []uint64{1, 1, 1, 1, 1, 1}
// 					data[i] = uint64(i + 1)
// 					pt := decoder.EncodeNew(data, bgvParams.MaxLevel())
// 					ct := encryptor.EncryptNew(pt)
// 					inputs[node.Node.ID()] = pkg.Operand{OperandLabel: pkg.OperandLabel(fmt.Sprintf("//%s/%s/in-0", node.Node.ID(), cLabel)), Ciphertext: ct}
// 				}

// 				localtest.Start()

// 				ctx := pkg.NewContext(&sessionID, nil)

// 				for _, node := range nodes {
// 					err = node.LoadCircuit(ctx, cDesc, cLabel)
// 					if err != nil {
// 						t.Fatal(err)
// 					}
// 				}

// 				g := new(errgroup.Group)
// 				for _, node := range nodes {
// 					node := node
// 					nodeDecoder := decoder.ShallowCopy()
// 					g.Go(func() error {
// 						out, errExec := node.Execute(ctx, cLabel, inputs[node.Node.ID()])
// 						if errExec != nil {
// 							return fmt.Errorf("node %s: %w", node.Node.ID(), errExec)
// 						}
// 						if len(out) > 0 {
// 							sess, _ := node.GetSessionFromID(sessionID)
// 							nodeSK, err := sess.GetSecretKey()
// 							if err != nil {
// 								t.Fatal(err)
// 							}
// 							// _ = recSk
// 							_ = nodeSK
// 							ptdec := bgv.NewDecryptor(bgvParams, nodeSK).DecryptNew(out[0].Ciphertext)
// 							// fmt.Println(nodeDecoder.DecodeUintNew(ptdec)[:6])
// 							require.Equal(t, []uint64{1, 2, 3, 4, 1, 1}, nodeDecoder.DecodeUintNew(ptdec)[:6])
// 						}
// 						return nil
// 					})
// 				}

// 				err = g.Wait()
// 				if err != nil {
// 					t.Fatal(err)
// 				}
// 			})
// 		}
// 	}
// }

func GetSha256Hex(b []byte, err error) string {
	return fmt.Sprintf("%x", sha256.Sum256(b))
}
