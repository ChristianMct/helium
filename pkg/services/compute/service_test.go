package compute

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/ldsec/helium/pkg/node"
	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/stretchr/testify/require"

	"github.com/tuneinsight/lattigo/v3/bfv"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"golang.org/x/sync/errgroup"
)

var rangeParam = []rlwe.ParametersLiteral{rlwe.TestPN12QP109} // , rlwe.TestPN13QP218, rlwe.TestPN14QP438, rlwe.TestPN15QP880}

type testSetting struct {
	N, T int
}

var testSettings = []testSetting{
	{N: 4},
}

var TestCircuits map[string]Circuit = map[string]Circuit{

	"Identity": func(ec EvaluationContext) error {
		op := ec.Input("//full-0/in-0")
		ec.Output(pkg.Operand{OperandLabel: "/out-0", Ciphertext: op.Ciphertext})
		return nil
	},

	"Sum2": func(ec EvaluationContext) error {
		op1 := ec.Input("//full-0/in-0")
		op2 := ec.Input("//full-1/in-0")
		res := ec.AddNew(op1.Ciphertext, op2.Ciphertext)
		ec.Output(pkg.Operand{OperandLabel: "/out-0", Ciphertext: res})
		return nil
	},

	"Mul2": func(ec EvaluationContext) error {
		op1 := ec.Input("//full-0/in-0")
		op2 := ec.Input("//full-1/in-0")
		res := ec.MulNew(op1.Ciphertext, op2.Ciphertext)
		ec.Relinearize(res, res)
		ec.Output(pkg.Operand{OperandLabel: "/out-0", Ciphertext: res})
		return nil
	},

	"Mul4CKS": func(e EvaluationContext) error {

		lvl2 := make(chan *bfv.Ciphertext, 2)

		op0 := e.Input("//full-0/in-0")
		op1 := e.Input("//full-1/in-0")

		go func() {
			ev := e.ShallowCopy()
			res := ev.MulNew(op0.Ciphertext, op1.Ciphertext)
			ev.Relinearize(res, res)
			fmt.Println("computed lvl 1,1")
			lvl2 <- res
		}()

		op2 := e.Input("//full-2/in-0")
		op3 := e.Input("//full-3/in-0")

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

		params := e.Parameters().Parameters
		opres := pkg.Operand{OperandLabel: "/res-0", Ciphertext: res}
		opout, err := e.CKS("CKS-0", opres, map[string]interface{}{
			"target":     "full-0",
			"aggregator": "full-0",
			"lvl":        params.MaxLevel(),
			"smudging":   1.0,
		})
		if err != nil {
			return err
		}

		e.Output(opout)

		fmt.Println("received from CKS")
		return nil
	},

	"Mul4PCKS": func(e EvaluationContext) error {

		lvl2 := make(chan *bfv.Ciphertext, 2)

		op0 := e.Input("//full-0/in-0")
		op1 := e.Input("//full-1/in-0")

		go func() {
			ev := e.ShallowCopy()
			res := ev.MulNew(op0.Ciphertext, op1.Ciphertext)
			ev.Relinearize(res, res)
			//fmt.Println("computed lvl 1,1")
			lvl2 <- res
		}()

		op2 := e.Input("//full-2/in-0")
		op3 := e.Input("//full-3/in-0")

		go func() {
			ev := e.ShallowCopy()
			res := ev.MulNew(op2.Ciphertext, op3.Ciphertext)
			ev.Relinearize(res, res)
			//fmt.Println("computed lvl 1,2")
			lvl2 <- res
		}()

		res1, res2 := <-lvl2, <-lvl2
		res := e.MulNew(res1, res2)
		e.Relinearize(res, res)
		//fmt.Println("computed lvl 0")

		params := e.Parameters().Parameters
		opres := pkg.Operand{OperandLabel: "/res-0", Ciphertext: res}
		opout, err := e.PCKS("PCKS-0", opres, map[string]interface{}{
			"target":     "full-0",
			"aggregator": "full-0",
			"lvl":        params.MaxLevel(),
			"smudging":   1.0,
		})
		if err != nil {
			return err
		}

		e.Output(opout)

		//fmt.Println("received from PCKS")
		return nil
	},

	"CloudMul4PCKS": func(e EvaluationContext) error {

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

		lvl2 := make(chan *bfv.Ciphertext, 2)
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
		opres := pkg.Operand{OperandLabel: "/res-0", Ciphertext: res}
		opout, err := e.PCKS("PCKS-0", opres, map[string]interface{}{
			"target":     "light-0",
			"aggregator": "helper-0",
			"lvl":        params.MaxLevel(),
			"smudging":   1.0,
		})
		if err != nil {
			return err
		}

		e.Output(opout)

		return nil
	},
}

func TestPeerEvalCircuit(t *testing.T) {

	for label, cDef := range TestCircuits {
		RegisterCircuit(label, cDef)
	}

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

				var cDesc = Signature{CircuitName: "Mul4PCKS"}

				sessionId := pkg.SessionID("test-session")
				cLabel := pkg.CircuitID("test-circuit-0")

				localtest := node.NewLocalTest(testConfig)

				params := localtest.Params
				bfvParams, _ := bfv.NewParameters(params, 65537)
				// initialise key generation
				kg := rlwe.NewKeyGenerator(params)
				sk := localtest.SkIdeal
				cpk := kg.GenPublicKey(sk)
				rlk := kg.GenRelinearizationKey(sk, 1)

				recSk, recPk := kg.GenKeyPair()

				var err error
				nodes := make([]*ComputeService, len(localtest.Nodes))
				for i := range localtest.Nodes {
					nodes[i], err = NewComputeService(localtest.Nodes[i])
					if err != nil {
						t.Fatal(err)
					}
					sess, exists := nodes[i].GetSessionFromID(sessionId)
					if !exists {
						t.Fatal("session should exist")
					}
					sess.PublicKey = cpk
					sess.Rlk = rlk
					sess.RegisterPkForNode("full-0", *recPk)
				}

				encryptor := bfv.NewEncryptor(bfvParams, cpk)
				decoder := bfv.NewEncoder(bfvParams)

				inputs := make(map[pkg.NodeID]pkg.Operand)
				for i, node := range nodes {
					data := []uint64{1, 1, 1, 1, 1, 1}
					data[i] = uint64(i + 1)
					pt := decoder.EncodeNew(data, bfvParams.MaxLevel())
					ct := encryptor.EncryptNew(pt)
					inputs[node.ID()] = pkg.Operand{OperandLabel: pkg.OperandLabel(fmt.Sprintf("//%s/%s/in-0", node.ID(), cLabel)), Ciphertext: ct}
				}

				localtest.Start()

				ctx := pkg.NewContext(&sessionId, nil)

				for _, node := range nodes {
					err = node.LoadCircuit(ctx, cDesc, cLabel)
					if err != nil {
						t.Fatal(err)
					}
				}

				g := new(errgroup.Group)
				for _, node := range nodes {
					node := node
					decoder := decoder.ShallowCopy()
					g.Go(func() error {
						node.Connect()
						out, err := node.Execute(ctx, cLabel, inputs[node.ID()])
						if err != nil {
							return fmt.Errorf("node %s: %s", node.ID(), err)
						}
						if len(out) > 0 {
							sess, _ := node.GetSessionFromID(sessionId)
							sk := sess.GetSecretKey()
							_ = recSk
							_ = sk
							ptdec := bfv.NewDecryptor(bfvParams, recSk).DecryptNew(out[0].Ciphertext)
							fmt.Println(decoder.DecodeUintNew(ptdec)[:6])
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

func TestCloudEvalCircuit(t *testing.T) {

	type client struct {
		*ComputeService
		bfv.Encoder
		bfv.Encryptor
	}

	for label, cDef := range TestCircuits {
		RegisterCircuit(label, cDef)
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
				// initialise key generation
				kg := rlwe.NewKeyGenerator(params)
				sk := localtest.SkIdeal

				sessionId := pkg.SessionID("test-session")

				// initialise the cloud with given parameters and a session
				sess, ok := clou.GetSessionFromID(sessionId)
				if !ok {
					t.Fatal("session should exist")
				}

				sess.Sk = sk.CopyNew()
				sess.PublicKey = kg.GenPublicKey(sk.CopyNew())
				sess.Rlk = kg.GenRelinearizationKey(sk.CopyNew(), 1)

				localtest.Start()

				decoder := bfv.NewEncoder(bfvParams)
				//idealDecryptor := bfv.NewDecryptor(bfvParams, sk.CopyNew())

				recSk, recPk := kg.GenKeyPair()
				sess.RegisterPkForNode("light-0", *recPk)

				for i := range clients {
					clients[i].Connect()
					clients[i].Encoder = decoder.ShallowCopy()
					clients[i].Encryptor = bfv.NewEncryptor(bfvParams, sess.PublicKey)
					cliSess, _ := clients[i].GetSessionFromID(sessionId)
					cliSess.RegisterPkForNode("light-0", *recPk)
				}

				var cSign = Signature{
					CircuitName: "CloudMul4PCKS",
					Delegate:    clou.ID(),
				}

				cLabel := pkg.CircuitID("test-circuit-0")
				ctx := pkg.NewContext(&sessionId, nil)

				for _, node := range nodes {
					err = node.LoadCircuit(ctx, cSign, cLabel)
					if err != nil {
						t.Fatal(err)
					}
				}

				g := new(errgroup.Group)

				g.Go(func() error {
					_, err = clou.Execute(ctx, cLabel)
					if err != nil {
						return fmt.Errorf("Node %s: %s", clou.ID(), err)
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
						op := pkg.Operand{OperandLabel: pkg.OperandLabel(fmt.Sprintf("//%s/%s/in-0", client.ID(), cLabel)), Ciphertext: ct}
						out, err := client.Execute(ctx, cLabel, op)
						if err != nil {
							return fmt.Errorf("client %s: %s", client.ID(), err)
						}
						if len(out) > 0 {

							require.NotNil(t, out[0].Ciphertext, "client %s should have non-nil output", client.ID())

							cliSess, _ := client.GetSessionFromID(sessionId)
							_ = recSk
							_ = cliSess
							decryptor := bfv.NewDecryptor(bfvParams, recSk)

							ptdec := decryptor.DecryptNew(out[0].Ciphertext)
							fmt.Println(decoder.DecodeUintNew(ptdec)[:6])
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

func GetSha256Hex(b []byte, err error) string {
	return fmt.Sprintf("%x", sha256.Sum256(b))
}
