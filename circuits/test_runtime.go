package circuits

import (
	"fmt"
	"log"

	"github.com/ChristianMct/helium/sessions"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
)

// TestRuntime is an implementation of the Runtime interface for testing circuits
// locally, without any node. Inputs are provided as plaintexts and encrypted on
// the fly under the test session's ideal secret key; outputs are collected.
type TestRuntime struct {
	*sessions.TestSession

	circuit Circuit
	md      *Metadata
	inputs  func(OperandID) *rlwe.Plaintext

	evaluator Evaluator
	outputs   map[string]*OutputOperand
}

// NewTestRuntime creates a TestRuntime for the evaluation of circuit c as described by cd,
// with the inputs provided by the given function.
func NewTestRuntime(tsess *sessions.TestSession, c Circuit, cd Descriptor, inputs func(OperandID) *rlwe.Plaintext) (*TestRuntime, error) {
	itf, err := c.Describe(cd.Signature, tsess.FHEParameters)
	if err != nil {
		return nil, err
	}
	md, err := Resolve(cd, itf, tsess.SessParams.Nodes)
	if err != nil {
		return nil, err
	}

	var rlk *rlwe.RelinearizationKey
	if itf.Keys.Rlk {
		rlk = tsess.KeyGen.GenRelinearizationKeyNew(tsess.SkIdeal)
	}
	gks := make([]*rlwe.GaloisKey, 0, len(itf.Keys.GaloisEls))
	for _, galEl := range itf.Keys.GaloisEls {
		gks = append(gks, tsess.KeyGen.GenGaloisKeyNew(galEl, tsess.SkIdeal))
	}

	tr := &TestRuntime{
		TestSession: tsess,
		circuit:     c,
		md:          md,
		inputs:      inputs,
		evaluator:   NewEvaluator(tsess.FHEParameters, rlwe.NewMemEvaluationKeySet(rlk, gks...)),
		outputs:     make(map[string]*OutputOperand, len(itf.Outputs)),
	}
	for name, id := range md.Outputs {
		tr.outputs[name] = NewOutputOperand(id)
	}
	return tr, nil
}

// Run evaluates the circuit and returns its outputs, by name.
func (tr *TestRuntime) Run() (map[string]Operand, error) {
	if err := tr.circuit.Eval(tr); err != nil {
		return nil, err
	}
	outs := make(map[string]Operand, len(tr.outputs))
	for name, oo := range tr.outputs {
		op, set := oo.Get()
		if !set {
			return nil, fmt.Errorf("output %s was not set by the circuit", name)
		}
		outs[name] = op
	}
	return outs, nil
}

// Metadata returns the resolved metadata of the circuit evaluation.
func (tr *TestRuntime) Metadata() *Metadata {
	return tr.md
}

func (tr *TestRuntime) Descriptor() Descriptor {
	return tr.md.Descriptor.Clone()
}

func (tr *TestRuntime) Parameters() sessions.FHEParameters {
	return tr.FHEParameters
}

func (tr *TestRuntime) Keys(Keys) {}

func (tr *TestRuntime) Input(p Port) *FutureOperand {
	id, has := tr.md.InputID(p)
	if !has {
		panic(fmt.Errorf("input %s is not declared in the circuit interface", p))
	}
	fo := NewFutureOperand(id)
	fo.Set(tr.encrypt(id))
	return fo
}

func (tr *TestRuntime) InputSum(name string, _ ...string) *FutureOperand {
	id, has := tr.md.SumID(name)
	if !has {
		panic(fmt.Errorf("summed input %s is not declared in the circuit interface", name))
	}
	fo := NewFutureOperand(id)

	ptAgg := rlwe.NewPlaintext(tr.RlweParams, tr.RlweParams.MaxLevel())
	for _, cid := range tr.md.SumInputs[name] {
		pt := tr.inputs(cid)
		if pt == nil {
			panic(fmt.Errorf("input provider returned nil input for %s", cid))
		}
		tr.RlweParams.RingQ().Add(ptAgg.Value, pt.Value, ptAgg.Value)
		*ptAgg.MetaData = *pt.MetaData
	}
	ct, err := tr.Encryptor.EncryptNew(ptAgg) // TODO: simulate CRS-based encryption
	if err != nil {
		panic(err)
	}
	fo.Set(ct)
	return fo
}

func (tr *TestRuntime) Output(name string) *OutputOperand {
	oo, has := tr.outputs[name]
	if !has {
		panic(fmt.Errorf("output %s is not declared in the circuit interface", name))
	}
	return oo
}

func (tr *TestRuntime) Evaluator() Evaluator {
	return tr.evaluator
}

func (tr *TestRuntime) Logf(msg string, v ...any) {
	log.Printf("[TestRuntime] %s\n", fmt.Sprintf(msg, v...))
}

func (tr *TestRuntime) encrypt(id OperandID) *rlwe.Ciphertext {
	pt := tr.inputs(id)
	if pt == nil {
		panic(fmt.Errorf("input provider returned nil input for %s", id))
	}
	ct, err := tr.Encryptor.EncryptNew(pt)
	if err != nil {
		panic(err)
	}
	return ct
}
