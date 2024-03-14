package objectstore

import (
	"encoding"
	"fmt"
)

// nullObjectStore is a type implementing the objectstore.ObjectStore interface with a NULL backend.
type nullObjectStore struct{}

// NewObjectStore creates a new ObjectStore instance.
func NewNullObjectStore() *nullObjectStore {
	return &nullObjectStore{}
}

func (objstore *nullObjectStore) Store(objectID string, object encoding.BinaryMarshaler) error {
	return nil
}

func (objstore *nullObjectStore) Load(objectID string, object encoding.BinaryUnmarshaler) error {
	return fmt.Errorf("Load: ObjectStore backend is NULL")
}

func (objstore *nullObjectStore) IsPresent(objectID string) (bool, error) {
	return false, fmt.Errorf("IsPresent: ObjectStore backend is NULL")
}

func (objstore *nullObjectStore) Close() error { return nil }
