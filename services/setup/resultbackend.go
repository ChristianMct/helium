package setup

import (
	"context"
	"fmt"

	"github.com/ChristianMct/helium/objectstore"
	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/sessions"
)

type objStoreResultBackend struct {
	store objectstore.ObjectStore
}

func newObjStoreResultBackend(os objectstore.ObjectStore) *objStoreResultBackend {
	osrb := new(objStoreResultBackend)
	osrb.store = os
	return osrb
}

func (osrb objStoreResultBackend) Has(ctx context.Context, sig protocols.Signature) (has bool, err error) {

	sessid, has := sessions.IDFromContext(ctx)
	if !has {
		return false, sessions.ErrIDNotFoundInContext
	}

	hasShare, err := osrb.store.IsPresent(fmt.Sprintf("%s/%s-aggshare", sessid, sig))
	if err != nil {
		return false, err
	}
	hasPd, err := osrb.store.IsPresent(fmt.Sprintf("%s/%s-desc", sessid, sig))
	if err != nil {
		return false, err
	}
	return hasShare && hasPd, nil
}

func (osrb objStoreResultBackend) Put(ctx context.Context, pd protocols.Descriptor, aggShare protocols.Share) error {

	sessid, has := sessions.IDFromContext(ctx)
	if !has {
		return sessions.ErrIDNotFoundInContext
	}

	// TODO: as transaction
	err := osrb.store.Store(fmt.Sprintf("%s/%s-aggshare", sessid, pd.Signature), aggShare.MHEShare)
	if err != nil {
		return err
	}
	err = osrb.store.Store(fmt.Sprintf("%s/%s-desc", sessid, pd.Signature), &pd)
	return err
}

func (osrb objStoreResultBackend) GetShare(ctx context.Context, sig protocols.Signature, share protocols.LattigoShare) (err error) { // TODO: replace by binary unmasharller and remove interface
	sessid, has := sessions.IDFromContext(ctx)
	if !has {
		return sessions.ErrIDNotFoundInContext
	}

	err = osrb.store.Load(fmt.Sprintf("%s/%s-aggshare", sessid, sig), share)
	return
}

func (osrb objStoreResultBackend) GetProtocolDesc(ctx context.Context, sig protocols.Signature) (pd *protocols.Descriptor, err error) {
	sessid, has := sessions.IDFromContext(ctx)
	if !has {
		return nil, sessions.ErrIDNotFoundInContext
	}
	pd = new(protocols.Descriptor)
	err = osrb.store.Load(fmt.Sprintf("%s/%s-desc", sessid, sig), pd)
	return
}
