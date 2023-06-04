// Package nullobjectstore contains a null-backend implementation of the interface objectstore.ObjectStore.
package nullobjectstore

import (
	"encoding"
	"fmt"
)

// ObjectStore is a type implementing the objectstore.ObjectStore interface with a NULL backend.
type ObjectStore struct{}

// NewObjectStore creates a new ObjectStore instance.
func NewObjectStore() *ObjectStore {
	return &ObjectStore{}
}

func (objstore *ObjectStore) Store(objectID string, object encoding.BinaryMarshaler) error {
	return nil
}

func (objstore *ObjectStore) Load(objectID string, object encoding.BinaryUnmarshaler) error {
	return fmt.Errorf("Load: ObjectStore backend is NULL")
}

func (objstore *ObjectStore) IsPresent(objectID string) (bool, error) {
	return false, fmt.Errorf("IsPresent: ObjectStore backend is NULL")
}

func (objstore *ObjectStore) Close() error { return nil }
