package objectstore

import (
	"encoding"
	"fmt"
	"log"

	"github.com/dgraph-io/badger/v4"
)

// badgerObjectStore is a type implementing the objectstore.ObjectStore interface with a permanent storage backend
// based on BadgerDB.
type badgerObjectStore struct {
	db          *badger.DB
	bytesStored int
}

// NewObjectStore creates a new ObjectStore instance.
func NewBadgerObjectStore(conf Config) (ks *badgerObjectStore, err error) {
	// SynchWrites writes any change to disk immediately.
	// Maximum size of a single log file = 10MB
	// Maximum size of memtable table = 5MB
	// Value Threshold for an entry to be stored in the log file = 0.5MB
	opt := badger.DefaultOptions(conf.DBPath).WithValueLogFileSize(10 * (1 << 20)).WithMemTableSize(5 * (1 << 20)).WithValueThreshold(1 << 19)
	opt.Logger = nil
	db, err := badger.Open(opt)
	if err != nil {
		return nil, fmt.Errorf("could not instantiate BadgerDB: %s", err)
	}

	return &badgerObjectStore{db: db, bytesStored: 0}, nil
}

func (objstore *badgerObjectStore) Store(objectID string, object encoding.BinaryMarshaler) error {
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

func (objstore *badgerObjectStore) Load(objectID string, object encoding.BinaryUnmarshaler) error {
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

func (objstore *badgerObjectStore) IsPresent(objectID string) (bool, error) {
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

func (objstore *badgerObjectStore) Close() error {
	log.Printf("Total bytes stored: %dB\n", objstore.bytesStored)
	return objstore.db.Close()
}
