// Package utils defines a set of utility functions and types used across the helium project.
package utils

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"

	"github.com/tuneinsight/lattigo/v4/rlwe"
)

// Set is a mutable set of elements of type T.
// Set is not safe for concurrent use.
type Set[T comparable] map[T]struct{}

var exists = struct{}{}

// NewEmptySet creates a new empty set.
func NewEmptySet[T comparable]() Set[T] {
	return make(map[T]struct{})
}

// NewSingletonSet creates a new set with a single element el.
func NewSingletonSet[T comparable](el T) Set[T] {
	return map[T]struct{}{el: exists}
}

// NewSet creates a new set with the elements els.
func NewSet[T comparable](els []T) Set[T] {
	s := make(map[T]struct{})
	for _, el := range els {
		s[el] = exists
	}
	return s
}

// Add adds an element el to the receiver set.
func (s *Set[T]) Add(el T) {
	if *s == nil {
		*s = NewEmptySet[T]()
	}
	(*s)[el] = exists
}

// AddAll adds all elements of set els into the receiver set.
func (s *Set[T]) AddAll(els Set[T]) {
	if *s == nil {
		*s = NewEmptySet[T]()
	}
	for el := range els {
		(*s)[el] = exists
	}
}

// Remove removes all elements els from the receiver set.
func (s Set[T]) Remove(els ...T) {
	for _, e := range els {
		delete(s, e)
	}
}

// Diff returns the set difference between the receiver and other.
func (s Set[T]) Diff(other Set[T]) Set[T] {
	sc := s.Copy()
	sc.Remove(other.Elements()...)
	return sc
}

// Contains returns whether an element el is in the receiver set.
func (s Set[T]) Contains(el T) bool {
	_, inSet := s[el]
	return inSet
}

// Includes returns whether the other set is a subset of the receiver set.
func (s Set[T]) Includes(other Set[T]) bool {
	if len(other) > len(s) {
		return false
	}
	for el := range other {
		if !s.Contains(el) {
			return false
		}
	}
	return true
}

// Disjoint returns whether the receiver and the other sets have an empty
// intersection.
func (s Set[T]) Disjoint(other Set[T]) bool {
	smallest, largest := s, other
	if len(other) < len(s) {
		smallest, largest = other, s
	}
	for el := range smallest {
		if largest.Contains(el) {
			return false
		}
	}
	return true
}

// Elements returns the set elements as a slice.
func (s Set[T]) Elements() []T {
	els := make([]T, 0, len(s))
	for el := range s {
		els = append(els, el)
	}
	return els
}

// Equals returns whether the receiver and other sets are equal.
func (s Set[T]) Equals(other Set[T]) bool {
	if len(s) != len(other) {
		return false
	}
	for el := range s {
		if !other.Contains(el) {
			return false
		}
	}
	return true
}

// Copy returns a new set containing the elements of the receiver
// set. It performs a shallow copy of the set elements.
func (s Set[T]) Copy() Set[T] {
	sc := NewEmptySet[T]()
	sc.AddAll(s)
	return sc
}

// GetRandomSliceOfSize returns a slice containing t random elements
// from s. The function panics if t > len(s).
func GetRandomSliceOfSize[T any](t int, s []T) []T {
	cid := make([]T, len(s))
	copy(cid, s)
	rand.Shuffle(len(cid), func(i, j int) {
		cid[i], cid[j] = cid[j], cid[i]
	})
	return cid[:t]
}

// GetRandomSetOfSize returns a set containing t random elements
// from s. The function panics if t > len(s).
func GetRandomSetOfSize[T comparable](t int, s Set[T]) Set[T] {
	return NewSet(GetRandomSliceOfSize(t, s.Elements()))
}

// SPrintDebugCiphertext is a debug function for obtaining a
// short string representation of a ciphertext by hashing its
// binary representation.
func SPrintDebugCiphertext(ct rlwe.Ciphertext) string {
	if ct.Value == nil {
		return "nil"
	}
	return getSha256Hex(ct.MarshalBinary())
}

func getSha256Hex(b []byte, _ error) string {
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

// MarshalJSONToFile attempts to write s to a file with file name filename,
// by calling the json.Marshal function.
func MarshalJSONToFile(s interface{}, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("could not open file: %w", err)
	}

	marshalled, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("could not marshal object: %w", err)
	}

	_, err = file.Write(marshalled)
	if err != nil {
		return fmt.Errorf("could not write to file: %w", err)
	}

	return file.Close()
}

// UnmarshalJSONFromFile attempts to load a json file with name filename,
// and to decode its content into s by calling the json.Unmarshal function.
func UnmarshalJSONFromFile(filename string, s interface{}) error {
	confFile, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("could not open file: %w", err)
	}

	cb, err := io.ReadAll(confFile)
	if err != nil {
		return fmt.Errorf("could not read file: %w", err)
	}

	err = json.Unmarshal(cb, s)
	if err != nil {
		return fmt.Errorf("could not parse the file: %w", err)
	}

	return nil
}

// ByteCountSI returns a string representation of a byte count b,
// by formatting it as a SI value.
func ByteCountSI(b uint64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB",
		float64(b)/float64(div), "kMGTPE"[exp])
}

// ByteCountIEC returns a string representation of a byte count b,
// by formatting it as a IEC value.
func ByteCountIEC(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB",
		float64(b)/float64(div), "KMGTPE"[exp])
}
