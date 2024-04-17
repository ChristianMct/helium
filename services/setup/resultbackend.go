package setup

import (
	"context"
	"fmt"

	"github.com/ChristianMct/helium/objectstore"
	"github.com/ChristianMct/helium/protocol"
	"github.com/ChristianMct/helium/session"
)

type objStoreResultBackend struct {
	store objectstore.ObjectStore
}

func newObjStoreResultBackend(os objectstore.ObjectStore) *objStoreResultBackend {
	osrb := new(objStoreResultBackend)
	osrb.store = os
	return osrb
}

func (osrb objStoreResultBackend) Has(ctx context.Context, sig protocol.Signature) (has bool, err error) {

	sessid, has := session.IDFromContext(ctx)
	if !has {
		return false, fmt.Errorf("session id not found in context")
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

func (osrb objStoreResultBackend) Put(ctx context.Context, pd protocol.Descriptor, aggShare protocol.Share) error {

	sessid, has := session.IDFromContext(ctx)
	if !has {
		return fmt.Errorf("session id not found in context")
	}

	// TODO: as transaction
	err := osrb.store.Store(fmt.Sprintf("%s/%s-aggshare", sessid, pd.Signature), aggShare.MHEShare)
	if err != nil {
		return err
	}
	err = osrb.store.Store(fmt.Sprintf("%s/%s-desc", sessid, pd.Signature), &pd)
	return err
}

func (osrb objStoreResultBackend) GetShare(ctx context.Context, sig protocol.Signature, share protocol.LattigoShare) (err error) { // TODO: replace by binary unmasharller and remove interface
	sessid, has := session.IDFromContext(ctx)
	if !has {
		return fmt.Errorf("session id not found in context")
	}

	err = osrb.store.Load(fmt.Sprintf("%s/%s-aggshare", sessid, sig), share)
	return
}

func (osrb objStoreResultBackend) GetProtocolDesc(ctx context.Context, sig protocol.Signature) (pd *protocol.Descriptor, err error) {
	sessid, has := session.IDFromContext(ctx)
	if !has {
		return nil, fmt.Errorf("session id not found in context")
	}
	err = osrb.store.Load(fmt.Sprintf("%s/%s-desc", sessid, sig), pd)
	return
}
