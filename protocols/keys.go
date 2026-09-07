package protocols

import (
	"context"
	"fmt"
	"strconv"

	"github.com/ChristianMct/helium/sessions"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
)

// KeyProvider is a view of an MHEMPC engine that exposes the outputs of the
// key-generation protocols as public keys. Its methods block until the
// corresponding protocol has completed.
type KeyProvider struct {
	e *MHEMPC
}

var _ sessions.PublicKeyProvider = (*KeyProvider)(nil)

// NewKeyProvider returns a KeyProvider for the given engine.
func NewKeyProvider(e *MHEMPC) *KeyProvider {
	return &KeyProvider{e: e}
}

// GetCollectivePublicKey returns the collective public key when available.
func (kp *KeyProvider) GetCollectivePublicKey(ctx context.Context) (*rlwe.PublicKey, error) {
	res, err := kp.getResult(ctx, Signature{Type: CKG})
	if err != nil {
		return nil, err
	}
	return res.(*rlwe.PublicKey), nil
}

// GetGaloisKey returns the Galois key for the given Galois element when available.
func (kp *KeyProvider) GetGaloisKey(ctx context.Context, galEl uint64) (*rlwe.GaloisKey, error) {
	res, err := kp.getResult(ctx, Signature{Type: RTG, Args: map[string]string{"GalEl": strconv.FormatUint(galEl, 10)}})
	if err != nil {
		return nil, err
	}
	return res.(*rlwe.GaloisKey), nil
}

// GetRelinearizationKey returns the relinearization key when available.
func (kp *KeyProvider) GetRelinearizationKey(ctx context.Context) (*rlwe.RelinearizationKey, error) {
	res, err := kp.getResult(ctx, Signature{Type: RKG})
	if err != nil {
		return nil, err
	}
	return res.(*rlwe.RelinearizationKey), nil
}

func (kp *KeyProvider) getResult(ctx context.Context, sig Signature) (interface{}, error) {
	pd, err := kp.e.AwaitCompleted(ctx, sig)
	if err != nil {
		return nil, fmt.Errorf("error while waiting for %s: %w", sig, err)
	}
	out, err := kp.e.GetOutput(ctx, pd)
	if err != nil {
		return nil, err
	}
	return out.Result, nil
}
