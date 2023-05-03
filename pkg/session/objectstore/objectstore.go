// Package objectstore defines an interface between the helium services and the session data.
package objectstore

import (
	"encoding"
)

// Config represents the ObjectStore configuration.
type Config struct {
	BackendName string // BackendName is a string defining the ObjectStore implementation to use.
	DBPath      string
}

// ObjectStore is an interface to store and retrieve session data.
type ObjectStore interface {
	// Store stores the binary-serializable `object` into the ObjectStore indexing it with the string `objectID`.
	Store(objectID string, object encoding.BinaryMarshaler) error

	// Load loads the binary-deserializable `object` from the ObjectStore indexing it with the string `objectID`.
	// the result is loaded directly into `object`
	Load(objectID string, object encoding.BinaryUnmarshaler) error

	// IsPresent checks if the object indexed with the string `objectID` is present in the ObjectStore.
	IsPresent(objectID string) (bool, error)

	// Close releases the resources allocated by the ObjectStore.
	Close() error
}
