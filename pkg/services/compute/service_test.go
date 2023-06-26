package compute_test

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"testing"

	"github.com/ldsec/helium/pkg/node"
	. "github.com/ldsec/helium/pkg/services/compute"
	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/stretchr/testify/require"

	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"golang.org/x/sync/errgroup"
)

var rangeParam = []rlwe.ParametersLiteral{ /*rlwe.TestPN12QP109 , */ rlwe.TestPN13QP218 /* rlwe.TestPN14QP438, rlwe.TestPN15QP880 */}

type testSetting struct {
	N, T int
}

var testSettings = []testSetting{
	{N: 4},
}

var TestCircuits = map[string]Circuit{

	"Identity": func(ec EvaluationContext) error {
		op := ec.Input("//full-0/in-0")
		ec.Output(pkg.Operand{OperandLabel: "/out-0", Ciphertext: op.Ciphertext}, "full-0")
		return nil
	},

	"Sum2": func(ec EvaluationContext) error {
		op1 := ec.Input("//full-0/in-0")
		op2 := ec.Input("//full-1/in-0")
		res := ec.AddNew(op1.Ciphertext, op2.Ciphertext)
		ec.Output(pkg.Operand{OperandLabel: "/out-0", Ciphertext: res}, "full-0")
		return nil
	},

	"Mul2": func(ec EvaluationContext) error {
		op1 := ec.Input("//full-0/in-0")
		op2 := ec.Input("//full-1/in-0")
		res := ec.MulNew(op1.Ciphertext, op2.Ciphertext)
		ec.Relinearize(res, res)
		ec.Output(pkg.Operand{OperandLabel: "/out-0", Ciphertext: res}, "full-0")
		return nil
	},

	"Mul4CKS": func(e EvaluationContext) error {

		lvl2 := make(chan *rlwe.Ciphertext, 2)

		op0 := e.Input("//full-0/in-0")
		op1 := e.Input("//full-1/in-0")

		go func() {
			ev := e.ShallowCopy()
			res := ev.MulNew(op0.Ciphertext, op1.Ciphertext)
			ev.Relinearize(res, res)
			lvl2 <- res
		}()

		op2 := e.Input("//full-2/in-0")
		op3 := e.Input("//full-3/in-0")

		go func() {
			ev := e.ShallowCopy()
			res := ev.MulNew(op2.Ciphertext, op3.Ciphertext)
			ev.Relinearize(res, res)
			lvl2 <- res
		}()

		res1, res2 := <-lvl2, <-lvl2
		res := e.MulNew(res1, res2)
		e.Relinearize(res, res)

		params := e.Parameters().Parameters
		opres := pkg.Operand{OperandLabel: "/res-0", Ciphertext: res}
		opout, err := e.CKS("CKS-0", opres, map[string]string{
			"target":     "full-0",
			"aggregator": "full-0",
			"lvl":        strconv.Itoa(params.MaxLevel()),
			"smudging":   "1.0",
		})
		if err != nil {
			return err
		}

		e.Output(opout, "full-0")

		return nil
	},

	"Mul4PCKS": func(e EvaluationContext) error {

		lvl2 := make(chan *rlwe.Ciphertext, 2)

		op0 := e.Input("//full-0/in-0")
		op1 := e.Input("//full-1/in-0")

		go func() {
			ev := e.ShallowCopy()
			res := ev.MulNew(op0.Ciphertext, op1.Ciphertext)
			ev.Relinearize(res, res)
			lvl2 <- res
		}()

		op2 := e.Input("//full-2/in-0")
		op3 := e.Input("//full-3/in-0")

		go func() {
			ev := e.ShallowCopy()
			res := ev.MulNew(op2.Ciphertext, op3.Ciphertext)
			ev.Relinearize(res, res)
			lvl2 <- res
		}()

		res1, res2 := <-lvl2, <-lvl2
		res := e.MulNew(res1, res2)
		e.Relinearize(res, res)

		params := e.Parameters().Parameters
		opres := pkg.Operand{OperandLabel: "/res-0", Ciphertext: res}
		opout, err := e.PCKS("PCKS-0", opres, map[string]string{
			"target":     "full-0",
			"aggregator": "full-0",
			"lvl":        strconv.Itoa(params.MaxLevel()),
			"smudging":   "1.0",
		})
		if err != nil {
			return err
		}

		e.Output(opout, "full-0")

		return nil
	},

	"CloudMul4CKS": func(e EvaluationContext) error {

		inputs := make(chan pkg.Operand, 4)
		inOpls := utils.NewSet([]pkg.OperandLabel{"//light-0/in-0", "//light-1/in-0", "//light-2/in-0", "//light-3/in-0"})
		for inOpl := range inOpls {
			inOpl := inOpl
			go func() {
				inputs <- e.Input(inOpl)
			}()
		}

		op0 := <-inputs
		op1 := <-inputs

		lvl2 := make(chan *rlwe.Ciphertext, 2)
		go func() {
			ev := e.ShallowCopy()
			res := ev.MulNew(op0.Ciphertext, op1.Ciphertext)
			ev.Relinearize(res, res)
			lvl2 <- res
		}()

		op2 := <-inputs
		op3 := <-inputs

		go func() {
			ev := e.ShallowCopy()
			res := ev.MulNew(op2.Ciphertext, op3.Ciphertext)
			ev.Relinearize(res, res)
			lvl2 <- res
		}()

		res1, res2 := <-lvl2, <-lvl2
		res := e.MulNew(res1, res2)
		e.Relinearize(res, res)

		params := e.Parameters().Parameters
		opres := pkg.Operand{OperandLabel: "//helper-0/res-0", Ciphertext: res}
		opout, err := e.CKS("DEC-0", opres, map[string]string{
			"target":     "light-0",
			"aggregator": "helper-0",
			"lvl":        strconv.Itoa(params.MaxLevel()),
			"smudging":   "1.0",
		})
		if err != nil {
			return err
		}

		e.Output(opout, "light-0")

		return nil
	},
	"psi-2PCKS": func(ec EvaluationContext) error {
		opIn1 := ec.Input("//light-0/in-0")
		opIn2 := ec.Input("//light-1/in-0")

		res := ec.MulNew(opIn1.Ciphertext, opIn2.Ciphertext)
		ec.Relinearize(res, res)
		opRes := pkg.Operand{OperandLabel: "//helper-0/out-0", Ciphertext: res}

		params := ec.Parameters().Parameters
		opOut, err := ec.PCKS("PCKSProtocolID", opRes, map[string]string{
			"target":     "external-0",
			"aggregator": "helper-0",
			"lvl":        strconv.Itoa(params.MaxLevel()),
			"smudging":   "1.0",
		})
		if err != nil {
			return err
		}

		ec.Output(opOut, "external-0")
		return nil
	},
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
	bfv.Encoder
	rlwe.Encryptor
}

func TestCloudEvalCircuit(t *testing.T) {

	for label, cDef := range TestCircuits {
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
				bfvParams, _ := bfv.NewParameters(params, 65537)
				// initialise key generation
				kg := rlwe.NewKeyGenerator(params)
				sk := localtest.SkIdeal

				clou.Session.Sk = sk.CopyNew()
				if err := clou.SetCollectivePublicKey(kg.GenPublicKey(sk.CopyNew())); err != nil {
					t.Fatal(err)
				}
				err := clou.SetRelinearizationKey(kg.GenRelinearizationKey(sk.CopyNew(), 1))
				if err != nil {
					t.Fatal(err)
				}

				localtest.Start()

				decoder := bfv.NewEncoder(bfvParams)

				for i := range clients {
					clients[i].Encoder = decoder.ShallowCopy()
					cpk, err := clou.GetCollectivePublicKey()
					if err != nil {
						t.Fatal(err)
					}
					clients[i].Encryptor = bfv.NewEncryptor(bfvParams, cpk)
				}

				var cSign = Signature{
					CircuitName: "CloudMul4CKS",
					Delegate:    clou.Node.ID(),
				}

				cLabel := pkg.CircuitID("test-circuit-0")
				ctx := pkg.NewContext(&sessionID, nil)

				for _, node := range nodes {
					err := node.LoadCircuit(ctx, cSign, cLabel)
					if err != nil {
						t.Fatal(err)
					}
				}

				g := new(errgroup.Group)

				g.Go(func() error {
					_, err := clou.Execute(ctx, cLabel)
					if err != nil {
						return fmt.Errorf("Node %s: %w", clou.Node.ID(), err)
					}
					return nil
				})

				for i, client := range clients {
					client := client
					i := i
					g.Go(func() error {
						data := []uint64{1, 1, 1, 1, 1, 1}
						data[i] = uint64(i + 1)
						pt := client.Encoder.EncodeNew(data, bfvParams.MaxLevel())
						ct := client.Encryptor.EncryptNew(pt)
						op := pkg.Operand{OperandLabel: pkg.OperandLabel(fmt.Sprintf("//%s/%s/in-0", client.Node.ID(), cLabel)), Ciphertext: ct}
						out, errExec := client.Execute(ctx, cLabel, op)
						if errExec != nil {
							return fmt.Errorf("client %s: %w", client.Node.ID(), errExec)
						}
						if len(out) > 0 {

							require.NotNil(t, out[0].Ciphertext, "client %s should have non-nil output", client.Node.ID())

							cliSess, _ := client.GetSessionFromID(sessionID)
							// _ = recSk
							_ = cliSess
							decryptor := bfv.NewDecryptor(bfvParams, cliSess.Sk)

							ptdec := decryptor.DecryptNew(out[0].Ciphertext)
							fmt.Println(decoder.DecodeUintNew(ptdec))
							require.Equal(t, []uint64{1, 2, 3, 4, 1, 1}, decoder.DecodeUintNew(ptdec)[:6])
						}
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

// TestCloudPCKS runs the compute phase and executes the psi-2-PCKS circuit to test the sending of the external receiver public key.
func TestCloudPCKS(t *testing.T) {

	for label, cDef := range TestCircuits {
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

				if ts.T != ts.N {
					t.Skip("T != N not yet supported in cloud-assisted setting")
				}

				var testConfig = node.LocalTestConfig{
					HelperNodes:   1,
					LightNodes:    2,
					ExternalNodes: 1,
					Session: &pkg.SessionParameters{
						RLWEParams: literalParams,
						T:          ts.T,
					},
				}

				localtest := node.NewLocalTest(testConfig)
				sessionID := pkg.SessionID("test-session")

				clou := cloud{Node: localtest.HelperNodes[0], Service: localtest.HelperNodes[0].GetComputeService()}
				clou.Session, _ = localtest.HelperNodes[0].GetSessionFromID(sessionID)

				external_0 := localtest.ExternalNodes[0]
				external_0Sess, _ := external_0.GetSessionFromID(sessionID)

				nodes := []*Service{clou.Service, external_0.GetComputeService()}

				clients := make([]client, len(localtest.LightNodes))
				for i, node := range localtest.LightNodes {
					clients[i].Node = node
					clients[i].Service = node.GetComputeService()
					clients[i].Session, _ = node.GetSessionFromID(sessionID)
					nodes = append(nodes, clients[i].Service)
				}

				params := localtest.Params
				bfvParams, _ := bfv.NewParameters(params, 65537)
				// initialise key generation
				kg := rlwe.NewKeyGenerator(params)
				sk := localtest.SkIdeal

				clou.Session.Sk = sk.CopyNew()
				err := clou.Session.SetCollectivePublicKey(kg.GenPublicKey(sk.CopyNew()))
				if err != nil {
					t.Fatal(err)
				}
				err = clou.SetRelinearizationKey(kg.GenRelinearizationKey(sk.CopyNew(), 1))
				if err != nil {
					t.Fatal(err)
				}

				localtest.Start()

				decoder := bfv.NewEncoder(bfvParams)

				recSk, recPk := kg.GenKeyPair()

				// save the secret key of the external node in its objectstore (emulate setup phase)
				err = external_0Sess.SetOuputSk(recSk)
				if err != nil {
					t.Fatal(err)
				}

				if err = clou.Session.SetOutputPkForNode("external-0", recPk); err != nil {
					t.Fatal(err)
				}
				if err = external_0Sess.SetOutputPkForNode("external-0", recPk); err != nil {
					t.Fatal(err)
				}

				for i := range clients {
					clients[i].Encoder = decoder.ShallowCopy()
					cpk, err := clou.Session.GetCollectivePublicKey()
					if err != nil {
						t.Fatal(err)
					}
					clients[i].Encryptor = bfv.NewEncryptor(bfvParams, cpk)
					cliSess, _ := clients[i].GetSessionFromID(sessionID)
					if err = cliSess.SetOutputPkForNode("external-0", recPk); err != nil {
						t.Fatal(err)
					}
				}

				var cSign = Signature{
					CircuitName: "psi-2PCKS",
					Delegate:    clou.Node.ID(),
				}

				cLabel := pkg.CircuitID("test-circuit-0")
				ctx := pkg.NewContext(&sessionID, nil)

				for _, node := range nodes {
					err := node.LoadCircuit(ctx, cSign, cLabel)
					if err != nil {
						t.Fatal(err)
					}
				}

				g := new(errgroup.Group)

				// execute cloud
				g.Go(func() error {
					_, err := clou.Execute(ctx, cLabel)
					if err != nil {
						return fmt.Errorf("Node %s: %w", clou.Node.ID(), err)
					}
					return nil
				})

				// execute clients
				for i, client := range clients {
					client := client
					i := i
					g.Go(func() error {
						data := make([]uint64, 6)
						data[i] = 1
						data[i+1] = 1
						pt := client.Encoder.EncodeNew(data, bfvParams.MaxLevel())
						ct := client.Encryptor.EncryptNew(pt)
						op := pkg.Operand{OperandLabel: pkg.OperandLabel(fmt.Sprintf("//%s/%s/in-0", client.Node.ID(), cLabel)), Ciphertext: ct}
						_, errExec := client.Execute(ctx, cLabel, op)
						if errExec != nil {
							return fmt.Errorf("client %s: %w", client.Node.ID(), errExec)
						}

						return nil
					})
				}

				// execute external receiver
				g.Go(func() error {
					out, err := external_0.GetComputeService().Execute(ctx, cLabel)
					if err != nil {
						return fmt.Errorf("Node %s: %w", external_0.ID(), err)
					}

					if len(out) > 0 {
						outputSk, err := external_0Sess.GetOutputSk()
						if err != nil {
							return fmt.Errorf("could not read receiver's (%s) private key: %w\n", external_0.ID(), err)

						}
						ptdec := bfv.NewDecryptor(bfvParams, outputSk).DecryptNew(out[0].Ciphertext)
						fmt.Println(decoder.DecodeUintNew(ptdec)[:6])
						require.Equal(t, []uint64{0, 1, 0, 0, 0, 0}, decoder.DecodeUintNew(ptdec)[:6])
					}
					return nil
				})

				err = g.Wait()
				if err != nil {
					t.Fatal(err)
				}
			})

		}
	}

}

func TestPeerEvalCircuit(t *testing.T) {

	t.Skip("skipped: current version focuses on the cloud-based model")

	for label, cDef := range TestCircuits {
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
					FullNodes: 4,
					Session: &pkg.SessionParameters{
						RLWEParams: literalParams,
						T:          ts.T,
					},
					InsecureChannels: true,
				}

				var cDesc = Signature{CircuitName: "Mul4CKS"}

				sessionID := pkg.SessionID("test-session")
				cLabel := pkg.CircuitID("test-circuit-0")

				localtest := node.NewLocalTest(testConfig)

				params := localtest.Params
				bfvParams, _ := bfv.NewParameters(params, 65537)
				// initialise key generation
				kg := rlwe.NewKeyGenerator(params)
				sk := localtest.SkIdeal
				cpk := kg.GenPublicKey(sk)
				rlk := kg.GenRelinearizationKey(sk, 1)

				// recSk, recPk := kg.GenKeyPair()

				var err error
				nodes := make([]peer, len(localtest.Nodes))
				for i, node := range localtest.Nodes {
					nodes[i].Node = node
					nodes[i].Service = node.GetComputeService()
					nodes[i].Session, _ = nodes[i].GetSessionFromID(sessionID)
					if err = nodes[i].Session.SetCollectivePublicKey(cpk); err != nil {
						t.Fatal(err)
					}
					// nodes[i].Session.Rlk = rlk
					if err = nodes[i].Session.SetRelinearizationKey(rlk); err != nil {
						t.Fatal(err)
					}
					// nodes[i].Session.RegisterPkForNode("full-0", *recPk)
				}

				encryptor := bfv.NewEncryptor(bfvParams, cpk)
				decoder := bfv.NewEncoder(bfvParams)

				inputs := make(map[pkg.NodeID]pkg.Operand)
				for i, node := range nodes {
					data := []uint64{1, 1, 1, 1, 1, 1}
					data[i] = uint64(i + 1)
					pt := decoder.EncodeNew(data, bfvParams.MaxLevel())
					ct := encryptor.EncryptNew(pt)
					inputs[node.Node.ID()] = pkg.Operand{OperandLabel: pkg.OperandLabel(fmt.Sprintf("//%s/%s/in-0", node.Node.ID(), cLabel)), Ciphertext: ct}
				}

				localtest.Start()

				ctx := pkg.NewContext(&sessionID, nil)

				for _, node := range nodes {
					err = node.LoadCircuit(ctx, cDesc, cLabel)
					if err != nil {
						t.Fatal(err)
					}
				}

				g := new(errgroup.Group)
				for _, node := range nodes {
					node := node
					nodeDecoder := decoder.ShallowCopy()
					g.Go(func() error {
						out, errExec := node.Execute(ctx, cLabel, inputs[node.Node.ID()])
						if errExec != nil {
							return fmt.Errorf("node %s: %w", node.Node.ID(), errExec)
						}
						if len(out) > 0 {
							sess, _ := node.GetSessionFromID(sessionID)
							nodeSK := sess.GetSecretKey()
							// _ = recSk
							_ = nodeSK
							ptdec := bfv.NewDecryptor(bfvParams, nodeSK).DecryptNew(out[0].Ciphertext)
							// fmt.Println(nodeDecoder.DecodeUintNew(ptdec)[:6])
							require.Equal(t, []uint64{1, 2, 3, 4, 1, 1}, nodeDecoder.DecodeUintNew(ptdec)[:6])
						}
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

func GetSha256Hex(b []byte, err error) string {
	return fmt.Sprintf("%x", sha256.Sum256(b))
}
