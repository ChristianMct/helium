package setup

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"testing"

	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/sessions"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	drlwe "github.com/tuneinsight/lattigo/v5/mhe"
)

// Description is a struct for specifying an MHE setup phase.
// It contains the information about the keys that should be generated:
// - Cpk: The collective public key
// - Rlk: The relinearization key
// - Gks: The Galois keys, identified by their Galois elements
type Description struct {
	Cpk bool
	Rlk bool
	Gks []uint64
}

// SignatureList provides utility functions for a list of signatures.
type SignatureList []protocols.Signature

// DescriptionToSignatureList converts a Description to a list of protocol signatures to be executed.
func DescriptionToSignatureList(sd Description) SignatureList {
	sl := make(SignatureList, 0, 3+len(sd.Gks))
	if sd.Cpk {
		sign := protocols.Signature{Type: protocols.CKG}
		sl = append(sl, sign)
	}
	if sd.Rlk {
		sl = append(sl, protocols.Signature{Type: protocols.RKG})
	}
	for _, gk := range sd.Gks {
		sign := protocols.Signature{Type: protocols.RTG, Args: map[string]string{"GalEl": strconv.FormatUint(gk, 10)}}
		sl = append(sl, sign)
	}
	return sl
}

// Contains checks if a list of signatures contains a given signature.
func (sl SignatureList) Contains(other protocols.Signature) bool {
	for _, sig := range sl {
		if sig.Equals(other) {
			return true
		}
	}
	return false
}

// String returns a string representation of the Description.
func (sd Description) String() string {
	return fmt.Sprintf(`
	{
		Cpk: %v,
		GaloisKeys: %v,
		Rlk: %v,
	}`, sd.Cpk, sd.Gks, sd.Rlk)
}

// CheckTestSetup checks if a public key provider is able to produce valid keys for a given test session and setup description.
func CheckTestSetup(ctx context.Context, t *testing.T, setup Description, n sessions.PublicKeyProvider, params rlwe.Parameters, skIdeal *rlwe.SecretKey, nParties int) {
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
		noiseBound := math.Log2(math.Sqrt(float64(decompositionVectorSize))*drlwe.NoiseGaloisKey(params, nParties)) + 1
		require.Less(t, rlwe.NoiseGaloisKey(rtk, skIdeal, params), noiseBound, "rtk for galEl %d should be correct", galEl)

	}

	// check RLK
	if setup.Rlk {
		rlk, err := n.GetRelinearizationKey(ctx)
		require.NoError(t, err)

		BaseRNSDecompositionVectorSize := params.BaseRNSDecompositionVectorSize(params.MaxLevelQ(), params.MaxLevelP())
		noiseBound := math.Log2(math.Sqrt(float64(BaseRNSDecompositionVectorSize))*drlwe.NoiseRelinearizationKey(params, nParties)) + 1

		require.Less(t, rlwe.NoiseRelinearizationKey(rlk, skIdeal, params), noiseBound)
	}
}
