// Package memobjectstore contains a main-memory-backend implementation of the interface objectstore.ObjectStore.
package memobjectstore

import (
	"encoding"
	"fmt"
	"sync"

	"github.com/tuneinsight/lattigo/v4/rlwe"
)

// ObjectStore is a type implementing the objectstore.ObjectStore interface with a main memory backend.
type ObjectStore struct {
	objstore map[string]any
	mtx      sync.RWMutex
}

// NewObjectStore creates a new ObjectStore instance.
func NewObjectStore() *ObjectStore {
	return &ObjectStore{objstore: make(map[string]any)}
}

func (objstore *ObjectStore) Store(objectID string, object encoding.BinaryMarshaler) error {
	objstore.mtx.Lock()
	defer objstore.mtx.Unlock()
	objstore.objstore[objectID] = object
	return nil
}

func (objstore *ObjectStore) Load(objectID string, object encoding.BinaryUnmarshaler) error {
	objstore.mtx.RLock()
	defer objstore.mtx.RUnlock()

	untyped_value, ok := objstore.objstore[objectID]
	if !ok {
		return fmt.Errorf("No value found for key string %s in in-memory ObjectStore", objectID)
	}

	switch value := object.(type) {
	case *rlwe.PublicKey:
		typed_value, ok := untyped_value.(*rlwe.PublicKey)
		if !ok {
			return fmt.Errorf("Type mismatch between requested type %T and actual stored type", value)
		}
		*value = *typed_value
		break

	case *rlwe.RelinearizationKey:
		typed_value, ok := untyped_value.(*rlwe.RelinearizationKey)
		if !ok {
			return fmt.Errorf("Type mismatch between requested type %T and actual stored type", value)
		}
		*value = *typed_value
		break

	case *rlwe.SwitchingKey:
		typed_value, ok := untyped_value.(*rlwe.SwitchingKey)
		if !ok {
			return fmt.Errorf("Type mismatch between requested type %T and actual stored type", value)
		}
		*value = *typed_value
		break
	case *rlwe.Ciphertext:
		typed_value, ok := untyped_value.(*rlwe.Ciphertext)
		if !ok {
			return fmt.Errorf("Type mismatch between requested type %T and actual stored type", value)
		}
		*value = *typed_value
		break
	default:
		return fmt.Errorf("Unexpected request type %T\n", value)
	}
	return nil
}

func (objstore *ObjectStore) IsPresent(objectID string) (bool, error) {
	objstore.mtx.RLock()
	defer objstore.mtx.RUnlock()

	_, ok := objstore.objstore[objectID]

	return ok, nil
}

func (objstore *ObjectStore) Close() error { return nil }
