// Package badgerobjectstore contains a permanent-storage-backend implementation of the interface objectstore.ObjectStore.
package badgerobjectstore

import (
	"encoding"
	"errors"
	"fmt"
	"log"

	"github.com/dgraph-io/badger/v3"
	"github.com/ldsec/helium/pkg/session/objectstore"
)

// ObjectStore is a type implementing the objectstore.ObjectStore interface with a permanent storage backend.
type ObjectStore struct {
	db          *badger.DB
	bytesStored int
}

// NewObjectStore creates a new ObjectStore instance.
func NewObjectStore(conf *objectstore.Config) (ks *ObjectStore, err error) {
	if conf == nil {
		return nil, errors.New("BadgerDB ObjectStore requires a Config")
	}
	// SynchWrites writes any change to disk immediately.
	// Maximum size of a single log file = 10MB
	// Maximum size of memtable table = 5MB
	// Value Threshold for an entry to be stored in the log file = 0.5MB
	opt := badger.DefaultOptions(conf.DBPath).WithValueLogFileSize(10 * (1 << 20)).WithMemTableSize(5 * (1 << 20)).WithValueThreshold(1 << 19)
	db, err := badger.Open(opt)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Could not instantiate BadgerDB: %s\n", err))
	}
	return &ObjectStore{db: db, bytesStored: 0}, nil
}

func (objstore *ObjectStore) Store(objectID string, object encoding.BinaryMarshaler) error {
	encodedObject, err := object.MarshalBinary()
	if err != nil {
		return err
	}
	objstore.bytesStored += len(encodedObject)
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

func (objstore *ObjectStore) Close() error {
	log.Printf("Total bytes stored: %dB\n", objstore.bytesStored)
	return objstore.db.Close()
}
