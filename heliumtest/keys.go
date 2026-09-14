package heliumtest

import (
	"context"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
)

// KeyProvider is an implementation of helium.PublicKeyProvider that generates the
// setup keys on the fly from an ideal secret key, for testing purposes.
// The implementation is not safe for concurrent use.
type KeyProvider struct {
	skIdeal *rlwe.SecretKey
	keygen  rlwe.KeyGenerator
}

// NewKeyProvider creates a new KeyProvider for the given parameters and ideal secret key.
func NewKeyProvider(params rlwe.Parameters, skIdeal *rlwe.SecretKey) *KeyProvider {
	return &KeyProvider{skIdeal: skIdeal, keygen: *rlwe.NewKeyGenerator(params)}
}

// GetCollectivePublicKey returns the collective public key for the session in ctx.
func (kp *KeyProvider) GetCollectivePublicKey(ctx context.Context) (*rlwe.PublicKey, error) {
	return kp.keygen.GenPublicKeyNew(kp.skIdeal), nil
}

// GetGaloisKey returns the galois key for the session in ctx and the given Galois element.
func (kp *KeyProvider) GetGaloisKey(ctx context.Context, galEl uint64) (*rlwe.GaloisKey, error) {
	return kp.keygen.GenGaloisKeyNew(galEl, kp.skIdeal), nil
}

// GetRelinearizationKey returns the relinearization key for the session in ctx.
func (kp *KeyProvider) GetRelinearizationKey(ctx context.Context) (*rlwe.RelinearizationKey, error) {
	return kp.keygen.GenRelinearizationKeyNew(kp.skIdeal), nil
}
