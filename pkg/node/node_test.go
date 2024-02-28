package node

import (
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
	"golang.org/x/net/context"
	"golang.org/x/sync/errgroup"
)

func failIfNonNil(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

type testNode struct {
	*Node
	compute.InputProvider
	OutputReceiver chan circuits.Output
	Outputs        map[circuits.ID]circuits.Output
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

	N := 4
	T := 3

	//params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{T: 79873, LogN: 13, LogQ: []int{54, 54, 54}, LogP: []int{55}}) // vecmul
	params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{T: 79873, LogN: 12, LogQ: []int{45, 45}, LogP: []int{19}}) // matmul
	failIfNonNil(t, err)
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
		cli.InputProvider = compute.NoInput
	}

	ctx := pkg.NewContext(&sessParams.ID, nil)

	hid := cloud.id

	app := App{
		SetupDescription: &setup.Description{
			Cpk: clientsId,
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
	g := errgroup.Group{}
	for _, node := range all {
		node := node
		g.Go(func() error {
			cdesc, outs, err := node.Run(ctx, app, node.InputProvider)
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
}

func TestNodeCompute(t *testing.T) {

	N := 4
	T := N
	//CIRCUIT_REP := 1

	//params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{T: 79873, LogN: 13, LogQ: []int{54, 54, 54}, LogP: []int{55}}) // vecmul
	params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{T: 79873, LogN: 12, LogQ: []int{45, 45}, LogP: []int{19}}) // matmul
	failIfNonNil(t, err)
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

	// cDesc := compute.Description{}
	// for i := 0; i < CIRCUIT_REP; i++ {
	// 	cDesc = append(cDesc, circuits.Signature{CircuitName: "matmul4-dec", CircuitID: pkg.CircuitID(fmt.Sprintf("test-circuit-%d", i))})
	// }

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
		// Circuits:      TestCircuits,
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
