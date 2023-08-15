package setup

import (
	"fmt"

	"github.com/ldsec/helium/pkg/objectstore"
	"github.com/ldsec/helium/pkg/protocols"
)

type ResultBackend interface {
	Has(sig protocols.Signature) (has bool, err error)
	Put(pd protocols.Descriptor, aggShare protocols.Share) error
	GetShare(sig protocols.Signature, share protocols.LattigoShare) (err error)
	GetProtocolDesc(sig protocols.Signature) (pd protocols.Descriptor, err error)
}

type objStoreResultBackend struct {
	store objectstore.ObjectStore
}

func newObjStoreResultBackend(os objectstore.ObjectStore) *objStoreResultBackend {
	osrb := new(objStoreResultBackend)
	osrb.store = os
	return osrb
}

func (osrb objStoreResultBackend) Has(sig protocols.Signature) (has bool, err error) {
	hasShare, err := osrb.store.IsPresent(fmt.Sprintf("%s-aggshare", sig))
	if err != nil {
		return false, err
	}
	hasPd, err := osrb.store.IsPresent(fmt.Sprintf("%s-desc", sig))
	if err != nil {
		return false, err
	}
	return hasShare && hasPd, nil
}

func (osrb objStoreResultBackend) Put(pd protocols.Descriptor, aggShare protocols.Share) error {
	// TOOD: as transaction
	err := osrb.store.Store(fmt.Sprintf("%s-aggshare", pd.Signature), aggShare.MHEShare)
	if err != nil {
		return err
	}
	err = osrb.store.Store(fmt.Sprintf("%s-desc", pd.Signature), &pd)
	return err
}

func (osrb objStoreResultBackend) GetShare(sig protocols.Signature, share protocols.LattigoShare) (err error) {
	err = osrb.store.Load(fmt.Sprintf("%s-aggshare", sig), share)
	return
}

func (osrb objStoreResultBackend) GetProtocolDesc(sig protocols.Signature) (pd protocols.Descriptor, err error) {
	err = osrb.store.Load(fmt.Sprintf("%s-desc", sig), &pd)
	return
}
