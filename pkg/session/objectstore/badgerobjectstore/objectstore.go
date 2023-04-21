// Package badgerobjectstore contains a permanent-storage-backend implementation of the interface objectstore.ObjectStore.
package badgerobjectstore

import (
	"encoding"
	"errors"
	"fmt"

	"github.com/dgraph-io/badger/v3"
	"github.com/ldsec/helium/pkg/session/objectstore"
)

// ObjectStore is a type implementing the objectstore.ObjectStore interface with a permanent storage backend.
type ObjectStore struct {
	db *badger.DB
}

// NewObjectStore creates a new ObjectStore instance.
func NewObjectStore(conf *objectstore.Config) (ks *ObjectStore, err error) {
	if conf == nil {
		return nil, errors.New("BadgerDB ObjectStore requires a Config")
	}
	opt := badger.DefaultOptions(conf.DBPath)
	db, err := badger.Open(opt)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Could not instantiate BadgerDB: %s\n", err))
	}
	return &ObjectStore{db: db}, nil
}

func (objstore *ObjectStore) Store(objectID string, object encoding.BinaryMarshaler) error {
	encodedObject, err := object.MarshalBinary()
	if err != nil {
		return err
	}
	err = objstore.db.Update(func(txn *badger.Txn) error {
		err := txn.Set([]byte(objectID), encodedObject)
		if err != nil {
			return err
		}
		return err
	})
	if err != nil {
		return err
	}
	return nil
}

func (objstore *ObjectStore) Load(objectID string, object encoding.BinaryUnmarshaler) error {
	var encodedObject []byte
	err := objstore.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(objectID))
		if err != nil {
			return err
		}
		encodedObject, err = item.ValueCopy(nil)
		if err != nil {
			return err
		}
		return err
	})
	if err != nil {
		return err
	}
	err = object.UnmarshalBinary(encodedObject)
	if err != nil {
		return err
	}
	return err
}

func (objstore *ObjectStore) IsPresent(objectID string) (bool, error) {
	present := false
	err := objstore.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get([]byte(objectID))

		if err == badger.ErrKeyNotFound {
			return nil
		}

		if err != nil {
			return err
		}

		present = true
		return nil
	})
	if err != nil {
		return present, err
	}

	return present, nil
}
