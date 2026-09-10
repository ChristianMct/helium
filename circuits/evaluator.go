package circuits

import (
	"fmt"

	"github.com/ChristianMct/helium/sessions"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he"
	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
	"github.com/tuneinsight/lattigo/v5/schemes/ckks"
)

// Evaluator is the homomorphic evaluator available to circuits. It extends
// Lattigo's scheme-agnostic he.Evaluator with the key-switching operations
// (rotations, conjugation, automorphisms, inner sums) under scheme-agnostic
// names, so that the evaluation keys required by a circuit can be inferred by
// symbolic execution (see Parse).
//
// Scheme returns the underlying Lattigo evaluator for scheme-specific
// operations; it is not available during symbolic execution, so circuits
// using it must declare their interface explicitly (see Circuit.Interface).
type Evaluator interface {
	he.Evaluator

	// Rotate rotates the slots of op0 by k positions (columns rotation in BGV).
	Rotate(op0 *rlwe.Ciphertext, k int, opOut *rlwe.Ciphertext) error
	// RotateNew rotates the slots of op0 by k positions into a new ciphertext.
	RotateNew(op0 *rlwe.Ciphertext, k int) (*rlwe.Ciphertext, error)
	// Conjugate applies the complex conjugation (CKKS) or the rows rotation (BGV).
	Conjugate(op0, opOut *rlwe.Ciphertext) error
	// ConjugateNew applies the complex conjugation (CKKS) or the rows rotation (BGV) into a new ciphertext.
	ConjugateNew(op0 *rlwe.Ciphertext) (*rlwe.Ciphertext, error)
	// Automorphism applies the automorphism of Galois element galEl.
	Automorphism(op0 *rlwe.Ciphertext, galEl uint64, opOut *rlwe.Ciphertext) error
	// InnerSum sums n batches of batchSize slots (see rlwe.Evaluator.InnerSum).
	InnerSum(op0 *rlwe.Ciphertext, batchSize, n int, opOut *rlwe.Ciphertext) error
	// Replicate replicates n batches of batchSize slots (see rlwe.Evaluator.Replicate).
	Replicate(op0 *rlwe.Ciphertext, batchSize, n int, opOut *rlwe.Ciphertext) error

	// Scheme returns the underlying scheme evaluator (*bgv.Evaluator or *ckks.Evaluator).
	Scheme() he.Evaluator
}

// NewEvaluator returns an Evaluator for the given parameters and evaluation keys.
func NewEvaluator(params sessions.FHEParameters, evk rlwe.EvaluationKeySet) Evaluator {
	switch p := params.(type) {
	case bgv.Parameters:
		return &bgvEvaluator{bgv.NewEvaluator(p, evk)}
	case ckks.Parameters:
		return &ckksEvaluator{ckks.NewEvaluator(p, evk)}
	default:
		panic(fmt.Errorf("unknown FHE parameters type: %T", params))
	}
}

// bgvEvaluator adapts a *bgv.Evaluator to the Evaluator interface.
type bgvEvaluator struct{ *bgv.Evaluator }

func (e *bgvEvaluator) Rotate(op0 *rlwe.Ciphertext, k int, opOut *rlwe.Ciphertext) error {
	return e.RotateColumns(op0, k, opOut)
}

func (e *bgvEvaluator) RotateNew(op0 *rlwe.Ciphertext, k int) (*rlwe.Ciphertext, error) {
	return e.RotateColumnsNew(op0, k)
}

func (e *bgvEvaluator) Conjugate(op0, opOut *rlwe.Ciphertext) error {
	return e.RotateRows(op0, opOut)
}

func (e *bgvEvaluator) ConjugateNew(op0 *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	return e.RotateRowsNew(op0)
}

func (e *bgvEvaluator) Scheme() he.Evaluator {
	return e.Evaluator
}

// ckksEvaluator adapts a *ckks.Evaluator to the Evaluator interface.
type ckksEvaluator struct{ *ckks.Evaluator }

func (e *ckksEvaluator) Scheme() he.Evaluator {
	return e.Evaluator
}
