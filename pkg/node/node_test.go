package node

import (
	"fmt"
	"sync"
	"testing"

	"github.com/ldsec/helium/pkg/circuits"
	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/services/compute"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v4/bgv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"golang.org/x/net/context"
	"gonum.org/v1/gonum/mat"
)

func failIfNonNil(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func TestHelium(t *testing.T) {

	//params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{T: 65537, LogN: 13, LogQ: []int{54, 54, 54}, LogP: []int{55}})         // vecmul
	params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{T: 1099511678977, LogN: 13, LogQ: []int{45, 45, 45}, LogP: []int{45}}) // matmul
	failIfNonNil(t, err)
	sessParams := pkg.SessionParameters{
		ID:         "test-session",
		RLWEParams: params.ParametersLiteral(),
		//T:          3,
	}

	lt := NewLocalTest(LocalTestConfig{
		LightNodes:  4,
		HelperNodes: 1,
		Session:     &sessParams,
	})

	lt.Start()

	//all := lt.Nodes
	cloud := lt.HelperNodes[0]
	clients := lt.LightNodes

	cDesc := compute.Description{
		circuits.Signature{CircuitName: "matmul4-dec", CircuitID: "test-circuit-0"},
		circuits.Signature{CircuitName: "matmul4-dec", CircuitID: "test-circuit-1"},
		circuits.Signature{CircuitName: "matmul4-dec", CircuitID: "test-circuit-2"},
		circuits.Signature{CircuitName: "matmul4-dec", CircuitID: "test-circuit-3"},
		// circuits.Signature{CircuitName: "mul4-dec", CircuitID: "test-circuit-4"},
		// circuits.Signature{CircuitName: "mul4-dec", CircuitID: "test-circuit-5"},
	}

	ctx := pkg.NewContext(&sessParams.ID, nil)

	app := App{
		InputProvider: &compute.NoInput,
		Circuits:      TestCircuits,
	}

	m := params.PlaintextDimensions().Cols

	a := mat.NewDense(m, m, nil)
	a.Apply(func(i, j int, v float64) float64 {
		return float64(i) + float64(2*j)
	}, a)

	cloud.RegisterPrecomputeHandler(func(ss *pkg.SessionStore, pkb compute.PublicKeyBackend) error {

		encoder := bgv.NewEncoder(params)

		cpk, err := pkb.GetCollectivePublicKey()
		if err != nil {
			return err
		}
		encryptor, err := bgv.NewEncryptor(params, cpk)
		if err != nil {
			return err
		}

		pta := make(map[int]*rlwe.Plaintext)
		cta := make(map[int]*rlwe.Ciphertext)
		sess, _ := ss.GetSessionFromID("test-session")

		diag := make(map[int][]uint64, m)
		for k := 0; k < m; k++ {
			diag[k] = make([]uint64, m)
			for i := 0; i < m; i++ {
				j := (i + k) % m
				diag[k][i] = uint64(a.At(i, j))
			}
		}

		cloud.Logf("generating encrypted matrix...")
		for di, d := range diag {
			pta[di] = rlwe.NewPlaintext(params, params.MaxLevel())
			encoder.Encode(d, pta[di])
			cta[di], err = encryptor.EncryptNew(pta[di])
			if err != nil {
				return err
			}
			sess.CiphertextStore.Store(pkg.Ciphertext{Ciphertext: *cta[di], CiphertextMetadata: pkg.CiphertextMetadata{ID: pkg.CiphertextID(fmt.Sprintf("//helper-0/mat-diag-%d", di))}})
		}
		cloud.Logf("done")

		return nil
	})

	sigs, outs, err := cloud.Run(ctx, app)
	if err != nil {
		t.Fatal(err)
	}

	b := mat.NewVecDense(m, nil)
	b.SetVec(1, 1)
	r := mat.NewVecDense(m, nil)

	r.MulVec(a, b)
	dataWant := make([]uint64, len(r.RawVector().Data))
	for i, v := range r.RawVector().Data {
		dataWant[i] = uint64(v)
	}

	//outs := make(chan compute.CircuitOutput)
	wg := new(sync.WaitGroup)
	wg.Add(len(clients))
	for i, node := range clients {
		i := i
		node := node
		var ip compute.InputProvider = func(ctx context.Context, inLabel pkg.OperandLabel) (*rlwe.Plaintext, error) {
			encoder := bgv.NewEncoder(params)
			_ = i
			data := make([]uint64, len(b.RawVector().Data))
			for i, v := range b.RawVector().Data {
				data[i] = uint64(v)
			}
			pt := bgv.NewPlaintext(params, params.MaxLevelQ())
			err := encoder.Encode(data, pt)
			if err != nil {
				return nil, err
			}
			return pt, nil
		}

		app := App{
			InputProvider: &ip,
			Circuits:      TestCircuits,
		}

		_, outi, err := node.Run(ctx, app)
		if err != nil {
			t.Fatal(err)
		}

		// sends all results back to the main test goroutine
		go func() {
			for co := range outi {
				//<-time.After(time.Second)
				outs <- co
			}
			node.Logf("is done")
			wg.Done()
		}()
	}

	go func() {
		for _, cd := range cDesc {
			sigs <- cd
		}
		close(sigs)
		wg.Wait()
	}()

	encoder := bgv.NewEncoder(params)
	for co := range outs {
		res := make([]uint64, params.PlaintextSlots())
		err = encoder.Decode(co.Pt, res)
		if err != nil {
			t.Fatal(err)
		}
		require.Equal(t, dataWant, res[:m])
	}

}
