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

func (s Set[T]) Remove(el ...T) {
	for _, e := range el {
		delete(s, e)
	}
}

func (s Set[T]) Diff(other Set[T]) Set[T] {
	sc := s.Copy()
	sc.Remove(other.Elements()...)
	return sc
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

func GetRandomSliceOfSize[T any](t int, nodes []T) []T {
	cid := make([]T, len(nodes))
	copy(cid, nodes)
	rand.Shuffle(len(cid), func(i, j int) {
		cid[i], cid[j] = cid[j], cid[i]
	})
	return cid[:t]
}

func GetRandomSetOfSize[T comparable](t int, nodes Set[T]) Set[T] {
	return NewSet(GetRandomSliceOfSize(t, nodes.Elements()))
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

type Triple[A, B, C any] struct {
	Fst A
	Snd B
	Trd C
}

func Zip[A, B, C any](as []A, bs []B, cs []C) []Triple[A, B, C] {
	length := len(as) * len(bs) * len(cs)
	triples := make([]Triple[A, B, C], length)

	idx := 0
	for _, a := range as {
		for _, b := range bs {
			for _, c := range cs {
				triples[idx] = Triple[A, B, C]{
					Fst: a,
					Snd: b,
					Trd: c,
				}
				idx++
			}
		}
	}
	return triples
}

func MarshalToFile(s interface{}, filename string) error {
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

func UnmarshalFromFile(filename string, s interface{}) error {
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
