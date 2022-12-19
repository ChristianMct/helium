package utils

import (
	"crypto/sha256"
	"fmt"

	"github.com/tuneinsight/lattigo/v4/rlwe"
)

var Exists = struct{}{}

type Set[T comparable] map[T]struct{}

func NewEmptySet[T comparable]() Set[T] {
	return make(map[T]struct{})
}

func NewSingletonSet[T comparable](el T) Set[T] {
	return map[T]struct{}{el: Exists}
}

func NewSet[T comparable](els []T) Set[T] {
	s := make(map[T]struct{})
	for _, el := range els {
		s[el] = Exists
	}
	return s
}

func (s Set[T]) Add(el T) {
	s[el] = Exists
}

func (s Set[T]) AddAll(el Set[T]) {
	for el := range el {
		s[el] = Exists
	}
}

func (s Set[T]) Remove(el T) {
	delete(s, el)
}

func (s Set[T]) Contains(el T) bool {
	_, inSet := s[el]
	return inSet
}

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

func (s Set[T]) Elements() []T {
	els := make([]T, 0, len(s))
	for el := range s {
		els = append(els, el)
	}
	return els
}

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

func (s Set[T]) Copy() Set[T] {
	sc := NewEmptySet[T]()
	sc.AddAll(s)
	return sc
}

func Must(bs []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return bs
}

func GetSha256Hex(b []byte, err error) string {
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

func PrintDebugCiphertext(ct rlwe.Ciphertext) string {
	if ct.Value == nil {
		return "nil"
	}
	return GetSha256Hex(ct.MarshalBinary())
}

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
