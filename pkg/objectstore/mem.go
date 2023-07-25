package objectstore

import (
	"encoding"
	"fmt"
	"sync"

	"github.com/tuneinsight/lattigo/v4/rlwe"
)

// ObjectStore is a type implementing the objectstore.ObjectStore interface with a main memory backend.
type memObjectStore struct {
	objstore map[string]any
	mtx      sync.RWMutex
}

// NewObjectStore creates a new ObjectStore instance.
func NewMemObjectStore() *memObjectStore {
	return &memObjectStore{objstore: make(map[string]any)}
}

func (objstore *memObjectStore) Store(objectID string, object encoding.BinaryMarshaler) error {
	objstore.mtx.Lock()
	defer objstore.mtx.Unlock()
	objstore.objstore[objectID] = object
	return nil
}

func (objstore *memObjectStore) Load(objectID string, object encoding.BinaryUnmarshaler) error {
	objstore.mtx.RLock()
	defer objstore.mtx.RUnlock()

	untypedValue, ok := objstore.objstore[objectID]
	if !ok {
		return fmt.Errorf("No value found for key string %s in in-memory ObjectStore", objectID)
	}

	switch value := object.(type) {
	case *rlwe.PublicKey:
		typedValue, ok := untypedValue.(*rlwe.PublicKey)
		if !ok {
			return fmt.Errorf("Type mismatch between requested type %T and actual stored type", value)
		}
		*value = *typedValue
		break

	case *rlwe.SecretKey:
		typedValue, ok := untypedValue.(*rlwe.SecretKey)
		if !ok {
			return fmt.Errorf("Type mismatch between requested type %T and actual stored type", value)
		}
		*value = *typedValue
		break

	case *rlwe.RelinearizationKey:
		typedValue, ok := untypedValue.(*rlwe.RelinearizationKey)
		if !ok {
			return fmt.Errorf("Type mismatch between requested type %T and actual stored type", value)
		}
		*value = *typedValue
		break

	case *rlwe.SwitchingKey:
		typedValue, ok := untypedValue.(*rlwe.SwitchingKey)
		if !ok {
			return fmt.Errorf("Type mismatch between requested type %T and actual stored type", value)
		}
		*value = *typedValue
		break

	case *rlwe.Ciphertext:
		typedValue, ok := untypedValue.(*rlwe.Ciphertext)
		if !ok {
			return fmt.Errorf("Type mismatch between requested type %T and actual stored type", value)
		}
		*value = *typedValue
		break

	default:
		return fmt.Errorf("Unexpected request type %T\n", value)
	}
	return nil
}

func (objstore *memObjectStore) IsPresent(objectID string) (bool, error) {
	objstore.mtx.RLock()
	defer objstore.mtx.RUnlock()

	_, ok := objstore.objstore[objectID]

	return ok, nil
}

func (objstore *memObjectStore) Close() error { return nil }
