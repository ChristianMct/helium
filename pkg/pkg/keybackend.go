package pkg

import (
	"context"
	"fmt"
	"sync"

	"github.com/tuneinsight/lattigo/v4/rlwe"
)

type PublicKeyBackend interface {
	GetCollectivePublicKey(ctx context.Context) (*rlwe.PublicKey, error)
	GetGaloisKey(ctx context.Context, galEl uint64) (*rlwe.GaloisKey, error)
	GetRelinearizationKey(ctx context.Context) (*rlwe.RelinearizationKey, error)
}

type MemoryKeyBackend struct {
	*rlwe.PublicKey
	GaloisKeys map[uint64]*rlwe.GaloisKey
	*rlwe.RelinearizationKey
}

func (pkb *MemoryKeyBackend) GetCollectivePublicKey(ctx context.Context) (cpk *rlwe.PublicKey, err error) {
	if pkb.PublicKey == nil {
		err = fmt.Errorf("no collective public key registered in this backend")
	}
	return pkb.PublicKey, err
}

func (pkb *MemoryKeyBackend) GetGaloisKey(ctx context.Context, galEl uint64) (gk *rlwe.GaloisKey, err error) {
	var has bool
	if gk, has = pkb.GaloisKeys[galEl]; !has {
		err = fmt.Errorf("no public galois key registered in this backend")
	}
	return gk, err
}

func (pkb *MemoryKeyBackend) GetRelinearizationKey(ctx context.Context) (rlk *rlwe.RelinearizationKey, err error) {
	if pkb.RelinearizationKey == nil {
		err = fmt.Errorf("no public relinearization key registered in this backend")
	}
	return pkb.RelinearizationKey, err
}

type CachedKeyBackend struct {
	sync.Mutex // TODO: could be more clever
	MemoryKeyBackend
	PublicKeyBackend
}

func NewCachedPublicKeyBackend(kb PublicKeyBackend) (ckb *CachedKeyBackend) {
	ckb = new(CachedKeyBackend)
	ckb.PublicKeyBackend = kb
	ckb.GaloisKeys = make(map[uint64]*rlwe.GaloisKey)
	return ckb
}

func (ckb *CachedKeyBackend) GetCollectivePublicKey(ctx context.Context) (*rlwe.PublicKey, error) {
	ckb.Lock()
	defer ckb.Unlock()
	cpk, err := ckb.MemoryKeyBackend.GetCollectivePublicKey(ctx)
	if err == nil {
		return cpk, nil
	}
	cpk, err = ckb.PublicKeyBackend.GetCollectivePublicKey(ctx)
	if err == nil {
		ckb.MemoryKeyBackend.PublicKey = cpk
		return cpk, nil
	}
	return nil, err
}

func (ckb *CachedKeyBackend) GetGaloisKey(ctx context.Context, galEl uint64) (*rlwe.GaloisKey, error) {
	ckb.Lock()
	defer ckb.Unlock()
	gk, err := ckb.MemoryKeyBackend.GetGaloisKey(ctx, galEl)
	if err == nil {
		return gk, nil
	}
	gk, err = ckb.PublicKeyBackend.GetGaloisKey(ctx, galEl)
	if err == nil {
		ckb.MemoryKeyBackend.GaloisKeys[galEl] = gk
		return gk, nil
	}
	return nil, err
}

func (ckb *CachedKeyBackend) GetRelinearizationKey(ctx context.Context) (*rlwe.RelinearizationKey, error) {
	ckb.Lock()
	defer ckb.Unlock()
	rk, err := ckb.MemoryKeyBackend.GetRelinearizationKey(ctx)
	if err == nil {
		return rk, nil
	}
	rk, err = ckb.PublicKeyBackend.GetRelinearizationKey(ctx)
	if err == nil {
		ckb.MemoryKeyBackend.RelinearizationKey = rk
		return rk, nil
	}
	return nil, err
}

type TestKeyBackend struct {
	skIdeal *rlwe.SecretKey
	keygen  rlwe.KeyGenerator
}

func NewTestKeyBackend(params rlwe.Parameters, skIdeal *rlwe.SecretKey) *TestKeyBackend {
	return &TestKeyBackend{skIdeal: skIdeal, keygen: *rlwe.NewKeyGenerator(params)}
}

func (tkb *TestKeyBackend) GetCollectivePublicKey(ctx context.Context) (*rlwe.PublicKey, error) {
	return tkb.keygen.GenPublicKeyNew(tkb.skIdeal)
}

func (tkb *TestKeyBackend) GetGaloisKey(ctx context.Context, galEl uint64) (*rlwe.GaloisKey, error) {
	return tkb.keygen.GenGaloisKeyNew(galEl, tkb.skIdeal)
}

func (tkb *TestKeyBackend) GetRelinearizationKey(ctx context.Context) (*rlwe.RelinearizationKey, error) {
	return tkb.keygen.GenRelinearizationKeyNew(tkb.skIdeal)
}
