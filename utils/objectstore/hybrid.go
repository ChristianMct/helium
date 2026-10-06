package objectstore

import (
	"encoding"
	"fmt"
	"log"
)

// hybridObjectStore is a type implementing the objectstore.ObjectStore interface with a hybrid storage backend.
// It combines an in-memory backend and a persistent backend.
type hybridObjectStore struct {
	badgerObjectStore *badgerObjectStore
	memObjectStore    *memObjectStore
}

// NewHybridObjectStore creates a new ObjectStore instance.
func NewHybridObjectStore(conf Config) (*hybridObjectStore, error) {
	badgerObjectStore, err := NewBadgerObjectStore(conf)
	if err != nil {
		return nil, fmt.Errorf("error while creating BadgerDB ObjectStore in hybrid ObjectStore :%w", err)
	}

	memObjectStore := NewMemObjectStore()

	objstore := &hybridObjectStore{
		badgerObjectStore: badgerObjectStore,
		memObjectStore:    memObjectStore,
	}

	return objstore, nil
}

func (objstore *hybridObjectStore) Store(objectID string, object encoding.BinaryMarshaler) error {
	// no error handling necessary for Store() in-memory ObjectStore
	objstore.memObjectStore.Store(objectID, object)

	if err := objstore.badgerObjectStore.Store(objectID, object); err != nil {
		return fmt.Errorf("error while storing in Hybrid ObjectStore :%w", err)
	}

	return nil
}

func (objstore *hybridObjectStore) Load(objectID string, object encoding.BinaryUnmarshaler) error {
	// attempt to load the object from the in-memory ObjectStore
	if err := objstore.memObjectStore.Load(objectID, object); err == nil {
		return nil
	}

	// in-memory ObjectStore failed, attempt to load the object from the persistent ObjectStore
	log.Printf("warning: could not load object %s from in-memory ObjectStore\n", objectID)
	if err := objstore.badgerObjectStore.Load(objectID, object); err != nil {
		log.Printf("error: could not load object %s from persistent ObjectStore: %s\n", objectID, err)
		return err
	}

	// propagate the object to the in-memory ObjectStore
	objectToStore, ok := object.(encoding.BinaryMarshaler)
	if ok {
		objstore.memObjectStore.Store(objectID, objectToStore)
	}
	log.Printf("warning: could not propagate object %s to in-memory ObjectStore\n", objectID)

	return nil
}

func (objstore *hybridObjectStore) IsPresent(objectID string) (bool, error) {
	// no error handling necessary for IsPresent() in-memory ObjectStore
	if present, _ := objstore.memObjectStore.IsPresent(objectID); present {
		return true, nil
	}

	//log.Printf("warning: object %s was not present in in-memory ObjectStore\n", objectID)
	present, err := objstore.badgerObjectStore.IsPresent(objectID)

	return present, err
}

func (objstore *hybridObjectStore) Close() error {
	if err := objstore.badgerObjectStore.Close(); err != nil {
		return err
	}
	return objstore.memObjectStore.Close()
}
