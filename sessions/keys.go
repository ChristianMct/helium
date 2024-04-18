package sessions

import (
	"context"
	"fmt"
	"sync"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
)

// PublicKeyProvider is an interface for retrieving public keys.
// Implementations return the keys for the session provided in the context.
// It is not specified whether implementations should block or return an
// error if the keys are not available.
//
// Notable implementations of this interface are setup.Service, and key stores
// like MemoryKeyStore and the CachedkeyStore.
type PublicKeyProvider interface {
	// GetCollectivePublicKey returns the collective public key for the session in ctx.
	GetCollectivePublicKey(ctx context.Context) (*rlwe.PublicKey, error)
	// GetGaloisKey returns the galois key for the session in ctx and the given Galois element.
	GetGaloisKey(ctx context.Context, galEl uint64) (*rlwe.GaloisKey, error)
	// GetRelinearizationKey returns the relinearization key for the session in ctx.
	GetRelinearizationKey(ctx context.Context) (*rlwe.RelinearizationKey, error)
}

// MemoryKeyStore is a simple in-memory implementation of PublicKeyProvider.
// This implementation is non-blocking and returns an error if the keys are not available.
type MemoryKeyStore struct {
	*rlwe.PublicKey
	GaloisKeys map[uint64]*rlwe.GaloisKey
	*rlwe.RelinearizationKey
}

// GetCollectivePublicKey returns the collective public key for the session in ctx.
// If the public key is not in the store, it returns an error.
func (pkb *MemoryKeyStore) GetCollectivePublicKey(ctx context.Context) (cpk *rlwe.PublicKey, err error) {
	if pkb.PublicKey == nil {
		err = fmt.Errorf("no collective public key registered in this backend")
	}
	return pkb.PublicKey, err
}

// GetGaloisKey returns the galois key for the session in ctx and the given Galois element.
// If the galois key is not in the store, it returns an error.
func (pkb *MemoryKeyStore) GetGaloisKey(ctx context.Context, galEl uint64) (gk *rlwe.GaloisKey, err error) {
	var has bool
	if gk, has = pkb.GaloisKeys[galEl]; !has {
		err = fmt.Errorf("no public galois key registered in this backend")
	}
	return gk, err
}

// GetRelinearizationKey returns the relinearization key for the session in ctx.
// If the relinearization key is not in the store, it returns an error.
func (pkb *MemoryKeyStore) GetRelinearizationKey(ctx context.Context) (rlk *rlwe.RelinearizationKey, err error) {
	if pkb.RelinearizationKey == nil {
		err = fmt.Errorf("no public relinearization key registered in this backend")
	}
	return pkb.RelinearizationKey, err
}

// CachedKeyBackend is a PublicKeyProvider queries a PublicKeyProvider for keys and caches them.
// The cached keys are cached indefinitely. This implementation is blocking if the underlying PublicKeyProvider
// is blocking. It returns an error if the underlying PublicKeyProvider returns an error.
// The implementation is safe for concurrent use.
type CachedKeyBackend struct {
	sync.Mutex // TODO: could be more clever
	MemoryKeyStore
	PublicKeyProvider
}

// NewCachedPublicKeyBackend creates a new CachedKeyBackend for the given PublicKeyProvider.
// The function panics if kb is nil.
func NewCachedPublicKeyBackend(kb PublicKeyProvider) (ckb *CachedKeyBackend) {
	if kb == nil {
		panic(fmt.Errorf("underlying PublicKeyProvider must not be nil"))
	}
	ckb = new(CachedKeyBackend)
	ckb.PublicKeyProvider = kb
	ckb.GaloisKeys = make(map[uint64]*rlwe.GaloisKey)
	return ckb
}

// GetCollectivePublicKey returns the collective public key for the session in ctx.
// The method returns an error if the key is not in the store and the underlying PublicKeyProvider returns an error.
func (ckb *CachedKeyBackend) GetCollectivePublicKey(ctx context.Context) (*rlwe.PublicKey, error) {
	ckb.Lock()
	defer ckb.Unlock()
	cpk, err := ckb.MemoryKeyStore.GetCollectivePublicKey(ctx)
	if err == nil {
		return cpk, nil
	}
	cpk, err = ckb.PublicKeyProvider.GetCollectivePublicKey(ctx)
	if err == nil {
		ckb.MemoryKeyStore.PublicKey = cpk
		return cpk, nil
	}
	return nil, err
}

// GetGaloisKey returns the galois key for the session in ctx and the given Galois element.
// The method returns an error if the key is not in the store and the underlying PublicKeyProvider returns an error.
func (ckb *CachedKeyBackend) GetGaloisKey(ctx context.Context, galEl uint64) (*rlwe.GaloisKey, error) {
	ckb.Lock()
	defer ckb.Unlock()
	gk, err := ckb.MemoryKeyStore.GetGaloisKey(ctx, galEl)
	if err == nil {
		return gk, nil
	}
	gk, err = ckb.PublicKeyProvider.GetGaloisKey(ctx, galEl)
	if err == nil {
		ckb.MemoryKeyStore.GaloisKeys[galEl] = gk
		return gk, nil
	}
	return nil, err
}

// GetRelinearizationKey returns the relinearization key for the session in ctx.
// The method returns an error if the key is not in the store and the underlying PublicKeyProvider returns an error.
func (ckb *CachedKeyBackend) GetRelinearizationKey(ctx context.Context) (*rlwe.RelinearizationKey, error) {
	ckb.Lock()
	defer ckb.Unlock()
	rk, err := ckb.MemoryKeyStore.GetRelinearizationKey(ctx)
	if err == nil {
		return rk, nil
	}
	rk, err = ckb.PublicKeyProvider.GetRelinearizationKey(ctx)
	if err == nil {
		ckb.MemoryKeyStore.RelinearizationKey = rk
		return rk, nil
	}
	return nil, err
}

// TestKeyProvider is an implementation of a PublicKeyProvider that generates
// the keys on the fly, and is used for testing purposes.
// The implementation is not safe for concurrent use.
type TestKeyProvider struct {
	skIdeal *rlwe.SecretKey
	keygen  rlwe.KeyGenerator
}

// NewTestKeyBackend creates a new TestKeyProvider for the given parameters and ideal secret key.
func NewTestKeyBackend(params rlwe.Parameters, skIdeal *rlwe.SecretKey) *TestKeyProvider {
	return &TestKeyProvider{skIdeal: skIdeal, keygen: *rlwe.NewKeyGenerator(params)}
}

// GetCollectivePublicKey returns the collective public key for the session in ctx.
func (tkb *TestKeyProvider) GetCollectivePublicKey(ctx context.Context) (*rlwe.PublicKey, error) {
	return tkb.keygen.GenPublicKeyNew(tkb.skIdeal), nil
}

// GetGaloisKey returns the galois key for the session in ctx and the given Galois element.
func (tkb *TestKeyProvider) GetGaloisKey(ctx context.Context, galEl uint64) (*rlwe.GaloisKey, error) {
	return tkb.keygen.GenGaloisKeyNew(galEl, tkb.skIdeal), nil
}

// GetRelinearizationKey returns the relinearization key for the session in ctx.
func (tkb *TestKeyProvider) GetRelinearizationKey(ctx context.Context) (*rlwe.RelinearizationKey, error) {
	return tkb.keygen.GenRelinearizationKeyNew(tkb.skIdeal), nil
}
