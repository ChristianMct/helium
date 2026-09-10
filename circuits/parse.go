package circuits

import (
	"errors"
	"fmt"
	"log"

	"github.com/ChristianMct/helium/sessions"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he"
	"github.com/tuneinsight/lattigo/v5/ring"
)

// errParseNoScheme is the panic value raised when a circuit requests the scheme
// evaluator during its symbolic execution.
var errParseNoScheme = errors.New("the scheme evaluator is not available during symbolic execution")

// Parse derives the interface of a circuit by symbolic execution of its evaluation function.
//
// The function is run end to end with a recording runtime: the declared ports and keys are
// collected, the inputs resolve immediately to placeholder ciphertexts (carrying a degree,
// a level and metadata, but no coefficients), and the evaluator records the keys required by
// the operations it is asked to perform (relinearization for MulRelin and Relinearize, Galois
// elements for Rotate, Conjugate, Automorphism, InnerSum and Replicate) without computing
// anything. Keys declared with Runtime.Keys are merged with the inferred ones.
//
// Hence, a circuit must be a deterministic function of its signature: it must not depend on the
// coefficients of the ciphertexts, and it must not use Evaluator.Scheme (whose operations cannot
// be recorded). Circuits that do not meet these requirements must declare their interface
// explicitly (see Circuit.Interface). Every declared output must be set when the function returns.
func Parse(eval func(Runtime) error, sig Signature, params sessions.FHEParameters) (itf Interface, err error) {
	if eval == nil {
		return Interface{}, fmt.Errorf("nil evaluation function")
	}
	pr := newParseRuntime(sig, params)

	func() {
		defer func() {
			if r := recover(); r != nil {
				if rerr, isErr := r.(error); isErr && errors.Is(rerr, errParseNoScheme) {
					err = fmt.Errorf("circuit %s uses the scheme evaluator: declare its interface explicitly", sig)
					return
				}
				err = fmt.Errorf("panic during the symbolic execution of circuit %s: %v", sig, r)
			}
		}()
		err = eval(pr)
	}()
	if err != nil {
		return Interface{}, fmt.Errorf("error during the symbolic execution of circuit %s: %w", sig, err)
	}

	if err := pr.itf.Validate(); err != nil {
		return Interface{}, fmt.Errorf("invalid interface for circuit %s: %w", sig, err)
	}
	for _, name := range pr.itf.Outputs {
		if _, set := pr.outputs[name].Get(); !set {
			return Interface{}, fmt.Errorf("invalid interface for circuit %s: output %s is never set", sig, name)
		}
	}
	return pr.itf, nil
}

// parseRuntime is the recording Runtime used by Parse.
type parseRuntime struct {
	sig    Signature
	params sessions.FHEParameters
	itf    Interface

	inputs  map[Port]*FutureOperand
	sums    map[string]*FutureOperand
	outputs map[string]*OutputOperand
	eval    *recordingEvaluator
}

func newParseRuntime(sig Signature, params sessions.FHEParameters) *parseRuntime {
	pr := &parseRuntime{
		sig:     sig,
		params:  params,
		inputs:  make(map[Port]*FutureOperand),
		sums:    make(map[string]*FutureOperand),
		outputs: make(map[string]*OutputOperand),
	}
	pr.eval = newRecordingEvaluator(params, &pr.itf)
	return pr
}

func (pr *parseRuntime) Descriptor() Descriptor {
	return Descriptor{Signature: pr.sig.Clone()}
}

func (pr *parseRuntime) Parameters() sessions.FHEParameters {
	return pr.params
}

func (pr *parseRuntime) Keys(k Keys) {
	pr.itf.Keys = pr.itf.Keys.Merge(k)
}

func (pr *parseRuntime) Input(p Port) *FutureOperand {
	if fo, has := pr.inputs[p]; has {
		return fo
	}
	pr.itf.Inputs = append(pr.itf.Inputs, p)
	fo := NewFutureOperand(NewOperandID(sessions.NodeID(p.Party()), "parse", p.Name()))
	fo.Set(pr.eval.placeholder(1, pr.eval.params.MaxLevel()))
	pr.inputs[p] = fo
	return fo
}

func (pr *parseRuntime) InputSum(name string, parties ...string) *FutureOperand {
	if fo, has := pr.sums[name]; has {
		return fo
	}
	pr.itf.SumInputs = append(pr.itf.SumInputs, SumPort{Name: name, Parties: parties})
	fo := NewFutureOperand(NewOperandID("parse", "parse", name))
	fo.Set(pr.eval.placeholder(1, pr.eval.params.MaxLevel()))
	pr.sums[name] = fo
	return fo
}

func (pr *parseRuntime) Output(name string) *OutputOperand {
	if oo, has := pr.outputs[name]; has {
		return oo
	}
	pr.itf.Outputs = append(pr.itf.Outputs, name)
	oo := NewOutputOperand(NewOperandID("parse", "parse", name))
	pr.outputs[name] = oo
	return oo
}

func (pr *parseRuntime) Evaluator() Evaluator {
	return pr.eval
}

func (pr *parseRuntime) Logf(format string, args ...interface{}) {
	log.Printf("[parse] "+format, args...)
}

// recordingEvaluator is the Evaluator used during symbolic execution: it records the
// keys required by the requested operations in the interface being built, and tracks the
// degree and level of the placeholder ciphertexts instead of computing on them.
type recordingEvaluator struct {
	params rlwe.Parameters
	meta   *rlwe.MetaData
	itf    *Interface
}

func newRecordingEvaluator(params sessions.FHEParameters, itf *Interface) *recordingEvaluator {
	return &recordingEvaluator{
		params: *params.GetRLWEParameters(),
		meta:   sessions.NewCiphertext(params, 0, 0).MetaData.CopyNew(),
		itf:    itf,
	}
}

// placeholder returns a ciphertext of the given degree and level, with metadata but without
// coefficients.
func (r *recordingEvaluator) placeholder(degree, level int) *rlwe.Ciphertext {
	polys := make([]ring.Poly, degree+1)
	for i := range polys {
		polys[i] = ring.Poly{Coeffs: make([][]uint64, level+1)}
	}
	return &rlwe.Ciphertext{Element: rlwe.Element[ring.Poly]{MetaData: r.meta.CopyNew(), Value: polys}}
}

// reshape turns opOut into a placeholder of the given degree and level, keeping its metadata.
func (r *recordingEvaluator) reshape(opOut *rlwe.Ciphertext, degree, level int) error {
	if opOut == nil {
		return fmt.Errorf("nil output ciphertext")
	}
	ph := r.placeholder(degree, level)
	opOut.Value = ph.Value
	if opOut.MetaData == nil {
		opOut.MetaData = ph.MetaData
	}
	return nil
}

// shape returns the degree and level of an operand (0 and the maximum level for scalars and vectors).
func (r *recordingEvaluator) shape(op rlwe.Operand) (degree, level int) {
	switch o := op.(type) {
	case *rlwe.Ciphertext:
		if o == nil {
			return 1, r.params.MaxLevel()
		}
		return o.Degree(), o.Level()
	case *rlwe.Plaintext:
		if o == nil {
			return 0, r.params.MaxLevel()
		}
		return 0, o.Level()
	default:
		return 0, r.params.MaxLevel()
	}
}

func (r *recordingEvaluator) needRlk() {
	r.itf.Keys.Rlk = true
}

func (r *recordingEvaluator) needGaloisEls(galEls ...uint64) {
	r.itf.Keys = r.itf.Keys.Merge(Keys{GaloisEls: galEls})
}

// linear returns the shape of the result of a linear operation between op0 and op1.
func (r *recordingEvaluator) linear(op0 *rlwe.Ciphertext, op1 rlwe.Operand) (degree, level int) {
	d0, l0 := r.shape(op0)
	d1, l1 := r.shape(op1)
	return max(d0, d1), min(l0, l1)
}

// product returns the shape of the tensor product between op0 and op1.
func (r *recordingEvaluator) product(op0 *rlwe.Ciphertext, op1 rlwe.Operand) (degree, level int) {
	d0, l0 := r.shape(op0)
	d1, l1 := r.shape(op1)
	return d0 + d1, min(l0, l1)
}

func (r *recordingEvaluator) GetRLWEParameters() *rlwe.Parameters {
	return &r.params
}

func (r *recordingEvaluator) GetEvaluatorBuffer() *rlwe.EvaluatorBuffers {
	return nil
}

func (r *recordingEvaluator) Add(op0 *rlwe.Ciphertext, op1 rlwe.Operand, opOut *rlwe.Ciphertext) error {
	d, l := r.linear(op0, op1)
	return r.reshape(opOut, d, l)
}

func (r *recordingEvaluator) AddNew(op0 *rlwe.Ciphertext, op1 rlwe.Operand) (*rlwe.Ciphertext, error) {
	d, l := r.linear(op0, op1)
	return r.placeholder(d, l), nil
}

func (r *recordingEvaluator) Sub(op0 *rlwe.Ciphertext, op1 rlwe.Operand, opOut *rlwe.Ciphertext) error {
	d, l := r.linear(op0, op1)
	return r.reshape(opOut, d, l)
}

func (r *recordingEvaluator) SubNew(op0 *rlwe.Ciphertext, op1 rlwe.Operand) (*rlwe.Ciphertext, error) {
	d, l := r.linear(op0, op1)
	return r.placeholder(d, l), nil
}

func (r *recordingEvaluator) Mul(op0 *rlwe.Ciphertext, op1 rlwe.Operand, opOut *rlwe.Ciphertext) error {
	d, l := r.product(op0, op1)
	return r.reshape(opOut, d, l)
}

func (r *recordingEvaluator) MulNew(op0 *rlwe.Ciphertext, op1 rlwe.Operand) (*rlwe.Ciphertext, error) {
	d, l := r.product(op0, op1)
	return r.placeholder(d, l), nil
}

func (r *recordingEvaluator) MulRelin(op0 *rlwe.Ciphertext, op1 rlwe.Operand, opOut *rlwe.Ciphertext) error {
	d, l := r.product(op0, op1)
	if d > 1 {
		r.needRlk()
	}
	return r.reshape(opOut, min(d, 1), l)
}

func (r *recordingEvaluator) MulRelinNew(op0 *rlwe.Ciphertext, op1 rlwe.Operand) (*rlwe.Ciphertext, error) {
	d, l := r.product(op0, op1)
	if d > 1 {
		r.needRlk()
	}
	return r.placeholder(min(d, 1), l), nil
}

func (r *recordingEvaluator) MulThenAdd(op0 *rlwe.Ciphertext, op1 rlwe.Operand, opOut *rlwe.Ciphertext) error {
	d, l := r.product(op0, op1)
	dOut, lOut := r.shape(opOut)
	return r.reshape(opOut, max(d, dOut), min(l, lOut))
}

func (r *recordingEvaluator) Relinearize(op0, opOut *rlwe.Ciphertext) error {
	d, l := r.shape(op0)
	if d > 1 {
		r.needRlk()
	}
	return r.reshape(opOut, 1, l)
}

func (r *recordingEvaluator) Rescale(op0, opOut *rlwe.Ciphertext) error {
	d, l := r.shape(op0)
	return r.reshape(opOut, d, max(l-1, 0))
}

func (r *recordingEvaluator) Rotate(op0 *rlwe.Ciphertext, k int, opOut *rlwe.Ciphertext) error {
	r.needGaloisEls(r.params.GaloisElement(k))
	d, l := r.shape(op0)
	return r.reshape(opOut, d, l)
}

func (r *recordingEvaluator) RotateNew(op0 *rlwe.Ciphertext, k int) (*rlwe.Ciphertext, error) {
	r.needGaloisEls(r.params.GaloisElement(k))
	d, l := r.shape(op0)
	return r.placeholder(d, l), nil
}

func (r *recordingEvaluator) Conjugate(op0, opOut *rlwe.Ciphertext) error {
	r.needGaloisEls(r.params.GaloisElementOrderTwoOrthogonalSubgroup())
	d, l := r.shape(op0)
	return r.reshape(opOut, d, l)
}

func (r *recordingEvaluator) ConjugateNew(op0 *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	r.needGaloisEls(r.params.GaloisElementOrderTwoOrthogonalSubgroup())
	d, l := r.shape(op0)
	return r.placeholder(d, l), nil
}

func (r *recordingEvaluator) Automorphism(op0 *rlwe.Ciphertext, galEl uint64, opOut *rlwe.Ciphertext) error {
	r.needGaloisEls(galEl)
	d, l := r.shape(op0)
	return r.reshape(opOut, d, l)
}

func (r *recordingEvaluator) InnerSum(op0 *rlwe.Ciphertext, batchSize, n int, opOut *rlwe.Ciphertext) error {
	r.needGaloisEls(rlwe.GaloisElementsForInnerSum(r.params, batchSize, n)...)
	d, l := r.shape(op0)
	return r.reshape(opOut, d, l)
}

func (r *recordingEvaluator) Replicate(op0 *rlwe.Ciphertext, batchSize, n int, opOut *rlwe.Ciphertext) error {
	r.needGaloisEls(rlwe.GaloisElementsForReplicate(r.params, batchSize, n)...)
	d, l := r.shape(op0)
	return r.reshape(opOut, d, l)
}

func (r *recordingEvaluator) Scheme() he.Evaluator {
	panic(errParseNoScheme)
}
