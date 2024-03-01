package node

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/ldsec/helium/pkg/circuits"
	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/services/compute"
	"github.com/ldsec/helium/pkg/services/setup"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v4/bgv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"golang.org/x/exp/maps"
	"golang.org/x/net/context"
	"golang.org/x/sync/errgroup"
)

type TestCircuit struct {
	circuits.Signature
	ExpResult uint64
}

type testSetting struct {
	N        int // N - total parties
	T        int // T - parties in the access structure
	Circuits []TestCircuit
	Reciever pkg.NodeID
	Rep      int // numer of repetition for each circuit
}

var testCircuits = []TestCircuit{
	{Signature: circuits.Signature{Name: "add-2-dec", Args: nil}, ExpResult: 1},
}

var testSettings = []testSetting{
	{N: 2, Circuits: testCircuits, Reciever: "light-0"},
	{N: 2, Circuits: testCircuits, Reciever: "helper-0"},
	{N: 3, T: 2, Circuits: testCircuits, Reciever: "light-0"},
	{N: 3, T: 2, Circuits: testCircuits, Reciever: "helper-0"},
	{N: 3, T: 2, Circuits: testCircuits, Reciever: "helper-0", Rep: 10},
}

type testNode struct {
	*Node
	compute.InputProvider
	OutputReceiver chan circuits.Output
	Outputs        map[circuits.ID]circuits.Output
}

func NewTestNodes(lt *LocalTest) (all, clients map[pkg.NodeID]*testNode, cloud *testNode) {
	all = make(map[pkg.NodeID]*testNode, len(lt.Nodes))
	cloud = &testNode{}
	cloud.Node = lt.HelperNodes[0]
	cloud.InputProvider = compute.NoInput
	cloud.Outputs = make(map[circuits.ID]circuits.Output)
	all[cloud.id] = cloud

	clients = make(map[pkg.NodeID]*testNode)
	for _, n := range lt.LightNodes {
		cli := &testNode{}
		cli.Node = n
		cli.InputProvider = compute.NoInput
		cli.Outputs = make(map[circuits.ID]circuits.Output)
		clients[n.id] = cli
		all[n.id] = cli
	}
	return
}

func NodeIDtoTestInput(nid string) []uint64 {
	num := strings.Trim(string(nid), "light-")
	i, err := strconv.ParseUint(num, 10, 64)
	if err != nil {
		panic(err)
	}
	return []uint64{i}
}

func TestNodeSetup(t *testing.T) {

	for _, ts := range testSettings {
		if ts.T == 0 {
			ts.T = ts.N
		}
		if ts.Rep == 0 {
			ts.Rep = 1
		}

		t.Run(fmt.Sprintf("NParty=%d/T=%d/rec=%s/rep=%d", ts.N, ts.T, ts.Reciever, ts.Rep), func(t *testing.T) {

			//params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{T: 79873, LogN: 13, LogQ: []int{54, 54, 54}, LogP: []int{55}}) // vecmul
			params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{T: 79873, LogN: 12, LogQ: []int{45, 45}, LogP: []int{19}}) // matmul
			require.Nil(t, err)
			sessParams := pkg.SessionParameters{
				ID:         "test-session",
				RLWEParams: params.ParametersLiteral(),
				T:          ts.T,
			}

			lt, err := NewLocalTest(LocalTestConfig{
				LightNodes:  ts.N,
				HelperNodes: 1,
				Session:     &sessParams,
			})
			require.Nil(t, err)

			testSess := lt.TestSession

			all, clients, cloud := NewTestNodes(lt)

			ctx := pkg.NewContext(&sessParams.ID, nil)

			hid := cloud.id

			app := App{
				SetupDescription: &setup.Description{
					Cpk: maps.Keys(clients),
					GaloisKeys: []struct {
						GaloisEl  uint64
						Receivers []pkg.NodeID
					}{
						{5, []pkg.NodeID{hid}},
						{25, []pkg.NodeID{hid}},
						{125, []pkg.NodeID{hid}},
					},
					Rlk: []pkg.NodeID{hid},
				},
			}

			lt.Start()
			//g, ctx := errgroup.WithContext(ctx)
			g, runctx := errgroup.WithContext(ctx)
			for _, node := range all {
				node := node
				g.Go(func() error {
					cdesc, outs, err := node.Run(runctx, app, node.InputProvider)
					if err != nil {
						return err
					}
					close(cdesc)
					_, has := <-outs
					require.False(t, has)
					return nil
				})
			}

			err = g.Wait()
			if err != nil {
				t.Fatal(err)
			}

			for _, node := range all {
				setup.CheckTestSetup(ctx, t, node.id, testSess, *app.SetupDescription, node)
			}
		})
	}
}

func TestNodeCompute(t *testing.T) {

	for _, ts := range testSettings {
		if ts.T == 0 {
			ts.T = ts.N
		}
		if ts.Rep == 0 {
			ts.Rep = 1
		}

		t.Run(fmt.Sprintf("NParty=%d/T=%d/rec=%s/rep=%d", ts.N, ts.T, ts.Reciever, ts.Rep), func(t *testing.T) {

			//params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{T: 79873, LogN: 13, LogQ: []int{54, 54, 54}, LogP: []int{55}}) // vecmul
			params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{T: 79873, LogN: 12, LogQ: []int{45, 45}, LogP: []int{19}}) // matmul
			require.Nil(t, err)
			sessParams := pkg.SessionParameters{
				ID:         "test-session",
				RLWEParams: params.ParametersLiteral(),
				T:          ts.T,
			}

			lt, err := NewLocalTest(LocalTestConfig{
				LightNodes:  ts.N,
				HelperNodes: 1,
				Session:     &sessParams,
			})
			require.Nil(t, err)

			testSess := lt.TestSession

			all, clients, cloud := NewTestNodes(lt)

			for _, cli := range clients {
				pt := rlwe.NewPlaintext(testSess.RlweParams, testSess.RlweParams.MaxLevel())
				testSess.Encoder.Encode(NodeIDtoTestInput(string(cli.id)), pt)
				cli.InputProvider = func(ctx context.Context, ol circuits.OperandLabel) (*rlwe.Plaintext, error) {
					return pt, nil
				}
			}

			ctx := pkg.NewContext(&sessParams.ID, nil)
			hid := cloud.id

			app := App{
				SetupDescription: &setup.Description{
					Cpk: maps.Keys(clients),
					GaloisKeys: []struct {
						GaloisEl  uint64
						Receivers []pkg.NodeID
					}{
						{5, []pkg.NodeID{hid}},
						{25, []pkg.NodeID{hid}},
						{125, []pkg.NodeID{hid}},
					},
					Rlk: []pkg.NodeID{hid},
				},
				Circuits: circuits.TestCircuits,
			}

			lt.Start()
			g, runctx := errgroup.WithContext(ctx)

			var cdescs chan chan<- circuits.Descriptor = make(chan chan<- circuits.Descriptor)
			for _, node := range all {
				node := node
				g.Go(func() error {
					cdescsn, outs, err := node.Run(runctx, app, node.InputProvider)
					if err != nil {
						return err
					}
					if node.id == hid {
						cdescs <- cdescsn
					}
					for out := range outs {
						node.Outputs[out.ID] = out
					}
					return nil
				})
			}

			nodemap := map[string]pkg.NodeID{"p1": "light-0", "p2": "light-1", "eval": "helper-0", "rec": ts.Reciever}
			cdesc := <-cdescs
			expResult := make(map[circuits.ID]uint64)
			for _, tc := range ts.Circuits {
				for i := 0; i < ts.Rep; i++ {
					cid := circuits.ID(fmt.Sprintf("%s-%d", tc.Name, i))
					cdesc <- circuits.Descriptor{Signature: circuits.Signature{Name: tc.Name}, ID: cid, NodeMapping: nodemap, Evaluator: hid}
					expResult[cid] = tc.ExpResult
				}
			}

			close(cdesc)
			err = g.Wait()
			if err != nil {
				t.Fatal(err)
			}

			rec := all[ts.Reciever]
			for cid, expRes := range expResult {
				out, has := rec.Outputs[cid]
				require.True(t, has, "reciever should have an output")
				delete(rec.Outputs, cid)
				pt := &rlwe.Plaintext{Operand: out.Ciphertext.Operand, Value: out.Ciphertext.Value[0]}
				res := make([]uint64, testSess.RlweParams.PlaintextSlots())
				testSess.Encoder.Decode(pt, res)
				//fmt.Println(out.OperandLabel, res[:10])
				require.Equal(t, expRes, res[0])
			}

			for nid, n := range all {
				require.Empty(t, n.Outputs, "node %s should have no extra outputs", nid)
			}

		})
	}
}

func TestNodeMatMul(t *testing.T) {

	N := 4
	T := N
	//CIRCUIT_REP := 1

	//params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{T: 79873, LogN: 13, LogQ: []int{54, 54, 54}, LogP: []int{55}}) // vecmul
	params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{T: 79873, LogN: 12, LogQ: []int{45, 45}, LogP: []int{19}}) // matmul
	require.Nil(t, err)
	sessParams := pkg.SessionParameters{
		ID:         "test-session",
		RLWEParams: params.ParametersLiteral(),
		T:          T,
	}

	lt, err := NewLocalTest(LocalTestConfig{
		LightNodes:  N,
		HelperNodes: 1,
		Session:     &sessParams,
	})
	require.Nil(t, err)

	testSess := lt.TestSession

	all := make([]testNode, 1+N)
	cloud := &all[0]
	cloud.Node = lt.HelperNodes[0]
	cloud.InputProvider = compute.NoInput

	clients := all[1:]
	clientsId := make([]pkg.NodeID, len(clients))
	for i, n := range lt.LightNodes {
		clientsId[i] = n.id
		cli := &clients[i]
		cli.Node = n
		pt := rlwe.NewPlaintext(testSess.RlweParams, testSess.RlweParams.MaxLevel())
		testSess.Encoder.Encode(NodeIDtoTestInput(string(n.id)), pt)
		cli.InputProvider = func(ctx context.Context, ol circuits.OperandLabel) (*rlwe.Plaintext, error) {
			return pt, nil
		}
	}

	ctx := pkg.NewContext(&sessParams.ID, nil)

	hid := cloud.id

	app := App{
		SetupDescription: &setup.Description{
			Cpk: sessParams.Nodes,
			GaloisKeys: []struct {
				GaloisEl  uint64
				Receivers []pkg.NodeID
			}{
				{5, []pkg.NodeID{hid}},
				{25, []pkg.NodeID{hid}},
				{125, []pkg.NodeID{hid}},
			},
			Rlk: []pkg.NodeID{hid},
		},
		// InputProvider: &compute.NoInput,
		Circuits: circuits.TestCircuits,
	}

	// m := params.PlaintextDimensions().Cols

	// a := mat.NewDense(m, m, nil)
	// a.Apply(func(i, j int, v float64) float64 {
	// 	return float64(i) + float64(2*j)
	// }, a)

	// cloud.RegisterPrecomputeHandler(func(ss *pkg.SessionStore, pkb compute.PublicKeyBackend) error {

	// 	encoder := bgv.NewEncoder(params)

	// 	cpk, err := pkb.GetCollectivePublicKey()
	// 	if err != nil {
	// 		return err
	// 	}
	// 	encryptor, err := bgv.NewEncryptor(params, cpk)
	// 	if err != nil {
	// 		return err
	// 	}

	// 	pta := make(map[int]*rlwe.Plaintext)
	// 	cta := make(map[int]*rlwe.Ciphertext)
	// 	sess, _ := ss.GetSessionFromID("test-session")

	// 	diag := make(map[int][]uint64, m)
	// 	for k := 0; k < m; k++ {
	// 		diag[k] = make([]uint64, m)
	// 		for i := 0; i < m; i++ {
	// 			j := (i + k) % m
	// 			diag[k][i] = uint64(a.At(i, j))
	// 		}
	// 	}

	// 	cloud.Logf("generating encrypted matrix...")
	// 	for di, d := range diag {
	// 		pta[di] = rlwe.NewPlaintext(params, params.MaxLevel())
	// 		encoder.Encode(d, pta[di])
	// 		cta[di], err = encryptor.EncryptNew(pta[di])
	// 		if err != nil {
	// 			return err
	// 		}
	// 		sess.CiphertextStore.Store(pkg.Ciphertext{Ciphertext: *cta[di], CiphertextMetadata: pkg.CiphertextMetadata{ID: pkg.CiphertextID(fmt.Sprintf("//helper-0/mat-diag-%d", di))}})
	// 	}
	// 	cloud.Logf("done")

	// 	return nil
	// })

	g, ctx := errgroup.WithContext(ctx)
	lt.Start()
	g.Go(func() error {
		_, _, err = cloud.Run(ctx, app, cloud.InputProvider)
		return err
	})

	// b := mat.NewVecDense(m, nil)
	// b.SetVec(1, 1)
	// r := mat.NewVecDense(m, nil)

	// r.MulVec(a, b)
	// dataWant := make([]uint64, len(r.RawVector().Data))
	// for i, v := range r.RawVector().Data {
	// 	dataWant[i] = uint64(v)
	// }

	//outs := make(chan compute.CircuitOutput)

	for _, node := range clients {
		//i := i
		node := node
		// var ip compute.InputProvider = func(ctx context.Context, inLabel pkg.OperandLabel) (*rlwe.Plaintext, error) {
		// 	encoder := bgv.NewEncoder(params)
		// 	_ = i
		// 	data := make([]uint64, len(b.RawVector().Data))
		// 	for i, v := range b.RawVector().Data {
		// 		data[i] = uint64(v)
		// 	}
		// 	pt := bgv.NewPlaintext(params, params.MaxLevelQ())
		// 	err := encoder.Encode(data, pt)
		// 	if err != nil {
		// 		return nil, err
		// 	}
		// 	return pt, nil
		// }

		// app := App{
		// 	InputProvider: &ip,
		// 	Circuits:      TestCircuits,
		// }

		g.Go(func() error {
			_, _, err := node.Run(ctx, app, node.InputProvider)
			return err
		})

		// sends all results back to the main test goroutine
		// go func() {
		// 	for co := range outi {
		// 		//<-time.After(time.Second)
		// 		outs <- co
		// 	}
		// 	node.Logf("is done")
		// 	wg.Done()
		// }()
	}
	err = g.Wait()
	if err != nil {
		t.Fatal(err)
	}

	// go func() {
	// 	for _, cd := range cDesc {
	// 		sigs <- cd
	// 	}
	// 	close(sigs)
	// 	wg.Wait()
	// }()

	// encoder := bgv.NewEncoder(params)

	// ptWant := bgv.NewPlaintext(params, params.MaxLevel())
	// encoder.Encode(dataWant, ptWant)

	// diff := params.RingQ().NewPoly()
	// coeffsBigint := make([]*big.Int, params.N())
	// for i := range coeffsBigint {
	// 	coeffsBigint[i] = new(big.Int)
	// }

	// for co := range outs {

	// 	params.RingQ().Sub(co.Pt.Value, ptWant.Value, diff)

	// 	params.RingQ().INTT(diff, diff)

	// 	params.RingQ().PolyToBigintCentered(diff, 1, coeffsBigint)

	// 	vari, min, max := rlwe.NormStats(coeffsBigint)
	// 	fmt.Printf("var=%f, min=%f, max=%f\n", vari, min, max)

	// 	res := make([]uint64, params.PlaintextSlots())
	// 	err = encoder.Decode(co.Pt, res)
	// 	if err != nil {
	// 		t.Fatal(err)
	// 	}
	// 	require.Equal(t, dataWant, res[:m])
	// }

}
