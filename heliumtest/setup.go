package heliumtest

import (
	"context"
	"math"
	"testing"

	"github.com/ChristianMct/helium"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	mhe "github.com/tuneinsight/lattigo/v6/multiparty"
)

// CheckSetup checks that a public key provider produces valid keys for the given
// test session and setup description.
func CheckSetup(ctx context.Context, t *testing.T, setup helium.SetupDescription, n helium.PublicKeyProvider, params rlwe.Parameters, skIdeal *rlwe.SecretKey, nParties int) {
	// check CPK
	if setup.Cpk {
		cpk, err := n.GetCollectivePublicKey(ctx)
		require.NoError(t, err)
		require.Less(t, rlwe.NoisePublicKey(cpk, skIdeal, params), math.Log2(math.Sqrt(float64(nParties))*params.NoiseFreshSK())+1)
	}

	// check RTG
	for _, galEl := range setup.Gks {
		rtk, err := n.GetGaloisKey(ctx, galEl)
		require.NoError(t, err)

		decompositionVectorSize := params.BaseRNSDecompositionVectorSize(params.MaxLevelQ(), params.MaxLevelP())
		noiseBound := math.Log2(math.Sqrt(float64(decompositionVectorSize))*mhe.NoiseGaloisKey(params, nParties)) + 1
		require.Less(t, rlwe.NoiseGaloisKey(rtk, skIdeal, params), noiseBound, "rtk for galEl %d should be correct", galEl)

	}

	// check RLK
	if setup.Rlk {
		rlk, err := n.GetRelinearizationKey(ctx)
		require.NoError(t, err)

		BaseRNSDecompositionVectorSize := params.BaseRNSDecompositionVectorSize(params.MaxLevelQ(), params.MaxLevelP())
		noiseBound := math.Log2(math.Sqrt(float64(BaseRNSDecompositionVectorSize))*mhe.NoiseRelinearizationKey(params, nParties)) + 1

		require.Less(t, rlwe.NoiseRelinearizationKey(rlk, skIdeal, params), noiseBound)
	}
}
