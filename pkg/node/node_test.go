package node

import (
	"testing"

	"github.com/ldsec/helium/pkg/circuits"
	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/services/compute"
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

func TestHelium(t *testing.T) {

	params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{T: 65537, LogN: 13, LogQ: []int{54, 54, 54}, LogP: []int{55}})
	failIfNonNil(t, err)
	sessParams := pkg.SessionParameters{
		ID:         "test-session",
		RLWEParams: params.ParametersLiteral().RLWEParametersLiteral(),
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
		circuits.Signature{CircuitName: "mul4-dec", CircuitID: "test-circuit-0"},
		circuits.Signature{CircuitName: "mul4-dec", CircuitID: "test-circuit-1"},
		circuits.Signature{CircuitName: "mul4-dec", CircuitID: "test-circuit-2"},
		circuits.Signature{CircuitName: "mul4-dec", CircuitID: "test-circuit-3"},
		circuits.Signature{CircuitName: "mul4-dec", CircuitID: "test-circuit-4"},
		circuits.Signature{CircuitName: "mul4-dec", CircuitID: "test-circuit-5"},
	}

	ctx := pkg.NewContext(&sessParams.ID, nil)

	g := new(errgroup.Group)

	g.Go(func() error {
		app := App{
			ComputeDescription: cDesc,
			InputProvider:      &compute.NoInput,
			OutputReceiver:     &compute.NoOutput,
			Circuits:           testCircuits,
		}
		cloud.Run(ctx, app)
		if err != nil {
			t.Fatal(err)
		}

		cloud.Logf("Run returned")
		return nil
	})

	resCount := 0
	resChan := make(chan []uint64, len(cDesc))

	for i, node := range clients {
		i := i
		node := node
		encoder := bgv.NewEncoder(params)
		g.Go(func() error {
			var ip compute.InputProvider = func(ctx context.Context, inLabel pkg.OperandLabel) (*rlwe.Plaintext, error) {
				data := []uint64{1, 1, 1, 1, 1, 1}
				data[i] = uint64(i + 1)
				pt := bgv.NewPlaintext(params, params.MaxLevelQ())
				err := encoder.Encode(data, pt)
				if err != nil {
					return nil, err
				}
				return pt, nil
			}

			var or compute.OutputReceiver = func(ctx context.Context, co compute.CircuitOutput) (err error) {
				res := make([]uint64, params.PlaintextSlots())
				err = encoder.Decode(co.Pt, res)
				if err != nil {
					return err
				}
				resChan <- res
				resCount++
				if resCount == len(cDesc) {
					close(resChan)
				}
				return nil
			}

			app := App{
				ComputeDescription: cDesc,
				InputProvider:      &ip,
				OutputReceiver:     &or,
				Circuits:           testCircuits,
			}

			err := node.Run(ctx, app)
			if err != nil {
				t.Fatal(err)
			}

			node.Logf("Run returned")

			return nil
		})

	}

	g.Wait()

	for res := range resChan {
		require.Equal(t, []uint64{1, 2, 3, 4, 1, 1}, res[:6])
	}

}
