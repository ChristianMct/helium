package objectstore

import (
	"encoding"
	"fmt"
	"reflect"
	"sync"
)

// memObjectStore is a type implementing the objectstore.ObjectStore interface with a main memory backend.
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

	untypedValue, isPresent := objstore.objstore[objectID]
	if !isPresent {
		return fmt.Errorf("no value found for key string %s in in-memory ObjectStore", objectID)
	}

	if reflect.TypeOf(object) != reflect.TypeOf(untypedValue) {
		return fmt.Errorf("type mismatch between requested type %T and actual stored type %T", object, untypedValue)
	}

	v1 := reflect.ValueOf(untypedValue).Elem()
	v2 := reflect.ValueOf(object).Elem()
	v2.Set(v1)
	return nil
}

func (objstore *memObjectStore) IsPresent(objectID string) (bool, error) {
	objstore.mtx.RLock()
	defer objstore.mtx.RUnlock()

	_, ok := objstore.objstore[objectID]

	return ok, nil
}

func (objstore *memObjectStore) Close() error { return nil }
