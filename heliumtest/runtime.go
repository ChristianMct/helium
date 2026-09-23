package heliumtest

import (
	"fmt"
	"log"

	"github.com/ChristianMct/helium"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// Runtime is an implementation of the helium.CircuitRuntime interface for testing circuits
// locally, without any node. Inputs are provided as plaintexts and encrypted on
// the fly under the test session's ideal secret key; outputs are collected.
type Runtime struct {
	*Sessions

	circuit helium.Circuit
	md      *helium.Metadata
	inputs  func(helium.OperandID) *rlwe.Plaintext

	evaluator helium.Evaluator
	outputs   map[string]*helium.OutputOperand
}

// NewRuntime creates a Runtime for the evaluation of circuit c as described by cd,
// with the inputs provided by the given function.
func NewRuntime(tsess *Sessions, c helium.Circuit, cd helium.Descriptor, inputs func(helium.OperandID) *rlwe.Plaintext) (*Runtime, error) {
	itf, err := c.Describe(cd.Signature, tsess.FHEParameters)
	if err != nil {
		return nil, err
	}
	md, err := helium.Resolve(cd, itf, tsess.SessParams.Nodes)
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

	tr := &Runtime{
		Sessions:  tsess,
		circuit:   c,
		md:        md,
		inputs:    inputs,
		evaluator: helium.NewEvaluator(tsess.FHEParameters, rlwe.NewMemEvaluationKeySet(rlk, gks...)),
		outputs:   make(map[string]*helium.OutputOperand, len(itf.Outputs)),
	}
	for name, id := range md.Outputs {
		tr.outputs[name] = helium.NewOutputOperand(id)
	}
	return tr, nil
}

// Run evaluates the circuit and returns its outputs, by name.
func (tr *Runtime) Run() (map[string]helium.Operand, error) {
	if err := tr.circuit.Eval(tr); err != nil {
		return nil, err
	}
	outs := make(map[string]helium.Operand, len(tr.outputs))
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
func (tr *Runtime) Metadata() *helium.Metadata {
	return tr.md
}

func (tr *Runtime) Descriptor() helium.Descriptor {
	return tr.md.Descriptor.Clone()
}

func (tr *Runtime) Parameters() helium.FHEParameters {
	return tr.FHEParameters
}

func (tr *Runtime) Keys(helium.Keys) {}

func (tr *Runtime) Input(p helium.Port) *helium.FutureOperand {
	id, has := tr.md.InputID(p)
	if !has {
		panic(fmt.Errorf("input %s is not declared in the circuit interface", p))
	}
	fo := helium.NewFutureOperand(id)
	fo.Set(tr.encrypt(id))
	return fo
}

func (tr *Runtime) InputSum(name string, _ ...string) *helium.FutureOperand {
	id, has := tr.md.SumID(name)
	if !has {
		panic(fmt.Errorf("summed input %s is not declared in the circuit interface", name))
	}
	fo := helium.NewFutureOperand(id)

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

func (tr *Runtime) Output(name string) *helium.OutputOperand {
	oo, has := tr.outputs[name]
	if !has {
		panic(fmt.Errorf("output %s is not declared in the circuit interface", name))
	}
	return oo
}

func (tr *Runtime) Evaluator() helium.Evaluator {
	return tr.evaluator
}

func (tr *Runtime) Logf(msg string, v ...any) {
	log.Printf("[heliumtest] %s\n", fmt.Sprintf(msg, v...))
}

func (tr *Runtime) encrypt(id helium.OperandID) *rlwe.Ciphertext {
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
