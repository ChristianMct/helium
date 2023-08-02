package compute

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/ldsec/helium/pkg"
	"github.com/ldsec/helium/pkg/protocols"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

// EvaluationContext defines the interface that is available to circuits to access
// their execution context.
type EvaluationContext interface {
	// Input reads an input operand with the given label from the context.
	Input(pkg.OperandLabel) pkg.Operand

	// Set registers the given operand to the context.
	Set(pkg.Operand)

	// Output outputs the given operand to the context.
	Output(pkg.Operand, pkg.NodeID)

	// DEC runs a DEC protocol over the provided operand within the context.
	DEC(in pkg.Operand, params map[string]string) (out pkg.Operand, err error)

	// PCKS runs a PCKS protocol over the provided operand within the context.
	PCKS(in pkg.Operand, params map[string]string) (out pkg.Operand, err error)

	// SubCircuit evaluates a sub-circuit within the context.
	SubCircuit(pkg.CircuitID, Circuit) (EvaluationContext, error)

	// Parameters returns the encryption parameters for the circuit.
	Parameters() bfv.Parameters

	bfv.Evaluator
}

// Circuit is a type for representing circuits, which are go functions interacting with
// a provided evaluation context.
type Circuit func(EvaluationContext) error

type CircuitDescription struct {
	InputSet, Ops, OutputSet utils.Set[pkg.OperandLabel]
	OutputsFor               map[pkg.NodeID]utils.Set[pkg.OperandLabel]
	KeySwitchOps             map[string]protocols.Descriptor
	NeedRlk                  bool
	GaloisKeys               utils.Set[uint64]
}

type circuitParserContext struct {
	dummyEvaluator
	cDesc       CircuitDescription
	circID      pkg.CircuitID
	SubCtx      map[pkg.CircuitID]*circuitParserContext
	params      bfv.Parameters
	nodeMapping map[string]pkg.NodeID
	l           sync.Mutex
}

func newCircuitParserCtx(cid pkg.CircuitID, params bfv.Parameters, nodeMapping map[string]pkg.NodeID) *circuitParserContext {
	cpc := &circuitParserContext{
		circID: cid,
		cDesc: CircuitDescription{
			InputSet:     utils.NewEmptySet[pkg.OperandLabel](),
			Ops:          utils.NewEmptySet[pkg.OperandLabel](),
			OutputSet:    utils.NewEmptySet[pkg.OperandLabel](),
			OutputsFor:   make(map[pkg.NodeID]utils.Set[pkg.OperandLabel]),
			KeySwitchOps: make(map[string]protocols.Descriptor),
			GaloisKeys:   make(utils.Set[uint64]),
		},
		SubCtx:      make(map[pkg.CircuitID]*circuitParserContext, 0),
		params:      params,
		nodeMapping: nodeMapping,
	}
	cpc.dummyEvaluator.ctx = cpc
	return cpc
}

func (e *circuitParserContext) CircuitDescription() CircuitDescription {
	return e.cDesc
}

func (e *circuitParserContext) String() string {
	e.l.Lock()
	defer e.l.Unlock()
	b, err := json.MarshalIndent(e, "", "\t")
	if err != nil {
		panic(err)
	}
	return string(b)
}

func (e *circuitParserContext) Execute(context.Context) error {
	return nil
}

func (e *circuitParserContext) LocalInputs([]pkg.Operand) error {
	return nil
}

func (e *circuitParserContext) LocalOutputs() chan pkg.Operand {
	return nil
}

func (e *circuitParserContext) Input(in pkg.OperandLabel) pkg.Operand {
	e.l.Lock()
	defer e.l.Unlock()
	e.cDesc.InputSet.Add(in.ForCircuit(e.circID).ForMapping(e.nodeMapping))
	return pkg.Operand{OperandLabel: in}
}

func (e *circuitParserContext) Set(op pkg.Operand) {
	e.l.Lock()
	defer e.l.Unlock()
	opl := op.OperandLabel.ForCircuit(e.circID).ForMapping(e.nodeMapping)
	e.cDesc.Ops.Add(opl)
}

func (e *circuitParserContext) Get(opl pkg.OperandLabel) pkg.Operand {
	e.l.Lock()
	defer e.l.Unlock()
	e.cDesc.Ops.Add(opl.ForCircuit(e.circID).ForMapping(e.nodeMapping))
	return pkg.Operand{OperandLabel: opl}
}

func (e *circuitParserContext) Output(out pkg.Operand, to pkg.NodeID) {
	e.l.Lock()
	defer e.l.Unlock()
	opl := out.OperandLabel.ForCircuit(e.circID).ForMapping(e.nodeMapping)
	e.cDesc.OutputSet.Add(opl)
	e.cDesc.Ops.Add(opl)

	outset, exists := e.cDesc.OutputsFor[to]
	if !exists {
		outset = utils.NewEmptySet[pkg.OperandLabel]()
		e.cDesc.OutputsFor[to] = outset
	}
	outset.Add(opl)
}

func (e *circuitParserContext) SubCircuit(id pkg.CircuitID, cd Circuit) (EvaluationContext, error) {
	e.l.Lock()
	defer e.l.Unlock()
	subCtx := newCircuitParserCtx(pkg.CircuitID(fmt.Sprintf("%s/%s", e.circID, id)), e.params, e.nodeMapping)
	e.SubCtx[id] = subCtx
	err := cd(subCtx)
	return subCtx, err
}

func (e *circuitParserContext) registerKeyOps(pd protocols.Descriptor) error {

	target, hasTarget := pd.Signature.Args["target"]
	if !hasTarget {
		return fmt.Errorf("protocol parameter should have a target")
	}

	if e.nodeMapping != nil {
		pd.Signature.Args["target"] = string(e.nodeMapping[target])
	}

	if _, exists := e.cDesc.KeySwitchOps[pd.Signature.String()]; exists {
		return fmt.Errorf("protocol with id %s exists", pd.Signature.String())
	}

	e.cDesc.KeySwitchOps[pd.Signature.String()] = pd
	return nil
}

func GetProtocolDescriptor(t protocols.Type, in pkg.Operand, params map[string]string) (pd protocols.Descriptor) {
	parm := make(map[string]string, len(params))
	for k, v := range params {
		parm[k] = v
	}
	parm["op"] = string(in.OperandLabel)
	pd = protocols.Descriptor{Signature: protocols.Signature{Type: t, Args: parm}}
	return pd
}

func (e *circuitParserContext) DEC(in pkg.Operand, params map[string]string) (out pkg.Operand, err error) {
	e.Set(in)
	e.l.Lock()
	defer e.l.Unlock()
	pd := GetProtocolDescriptor(protocols.DEC, in, params)
	if err = e.registerKeyOps(pd); err != nil {
		panic(err)
	}
	return pkg.Operand{OperandLabel: pkg.OperandLabel(fmt.Sprintf("%s-%s-out", in.OperandLabel, pd.Signature.Type))}, nil
}

func (e *circuitParserContext) PCKS(in pkg.Operand, params map[string]string) (out pkg.Operand, err error) {
	e.Set(in)
	e.l.Lock()
	defer e.l.Unlock()
	pd := GetProtocolDescriptor(protocols.PCKS, in, params)
	if err = e.registerKeyOps(pd); err != nil {
		panic(err)
	}
	return pkg.Operand{OperandLabel: pkg.OperandLabel(fmt.Sprintf("%s-%s-out", in.OperandLabel, pd.Signature.Type))}, nil
}

func (e *circuitParserContext) Parameters() bfv.Parameters {
	e.l.Lock()
	defer e.l.Unlock()
	return e.params
}

func (e *circuitParserContext) Relinearize(ctIn *rlwe.Ciphertext, ctOut *rlwe.Ciphertext) {
	e.l.Lock()
	defer e.l.Unlock()
	e.cDesc.NeedRlk = true
}

func (e *circuitParserContext) RelinearizeNew(ctIn *rlwe.Ciphertext) (ctOut *rlwe.Ciphertext) {
	e.l.Lock()
	defer e.l.Unlock()
	e.cDesc.NeedRlk = true
	return nil
}

type dummyEvaluator struct{ ctx *circuitParserContext }

func (de dummyEvaluator) Add(ctIn *rlwe.Ciphertext, op1 rlwe.Operand, ctOut *rlwe.Ciphertext) {}

func (de dummyEvaluator) AddNew(ctIn *rlwe.Ciphertext, op1 rlwe.Operand) (ctOut *rlwe.Ciphertext) {
	return nil
}

func (de dummyEvaluator) AddNoMod(ctIn *rlwe.Ciphertext, op1 rlwe.Operand, ctOut *rlwe.Ciphertext) {}

func (de dummyEvaluator) AddNoModNew(ctIn *rlwe.Ciphertext, op1 rlwe.Operand) (ctOut *rlwe.Ciphertext) {
	return nil
}

func (de dummyEvaluator) Sub(ctIn *rlwe.Ciphertext, op1 rlwe.Operand, ctOut *rlwe.Ciphertext) {}

func (de dummyEvaluator) SubNew(ctIn *rlwe.Ciphertext, op1 rlwe.Operand) (ctOut *rlwe.Ciphertext) {
	return nil
}

func (de dummyEvaluator) SubNoMod(ctIn *rlwe.Ciphertext, op1 rlwe.Operand, ctOut *rlwe.Ciphertext) {}

func (de dummyEvaluator) SubNoModNew(ctIn *rlwe.Ciphertext, op1 rlwe.Operand) (ctOut *rlwe.Ciphertext) {
	return nil
}

func (de dummyEvaluator) Neg(ctIn *rlwe.Ciphertext, ctOut *rlwe.Ciphertext) {}

func (de dummyEvaluator) NegNew(ctIn *rlwe.Ciphertext) (ctOut *rlwe.Ciphertext) {
	return nil
}

func (de dummyEvaluator) Reduce(ctIn *rlwe.Ciphertext, ctOut *rlwe.Ciphertext) {}

func (de dummyEvaluator) ReduceNew(ctIn *rlwe.Ciphertext) (ctOut *rlwe.Ciphertext) {
	return nil
}

func (de dummyEvaluator) AddScalar(ctIn *rlwe.Ciphertext, scalar uint64, ctOut *rlwe.Ciphertext) {}

func (de dummyEvaluator) MulScalar(ctIn *rlwe.Ciphertext, scalar uint64, ctOut *rlwe.Ciphertext) {}

func (de dummyEvaluator) MulScalarAndAdd(ctIn *rlwe.Ciphertext, scalar uint64, ctOut *rlwe.Ciphertext) {
}

func (de dummyEvaluator) MulScalarNew(ctIn *rlwe.Ciphertext, scalar uint64) (ctOut *rlwe.Ciphertext) {
	return nil
}

func (de dummyEvaluator) Rescale(ctIn *rlwe.Ciphertext, ctOut *rlwe.Ciphertext) {}

func (de dummyEvaluator) RescaleTo(level int, ctIn *rlwe.Ciphertext, ctOut *rlwe.Ciphertext) {}

func (de dummyEvaluator) Mul(ctIn *rlwe.Ciphertext, op1 rlwe.Operand, ctOut *rlwe.Ciphertext) {}

func (de dummyEvaluator) MulNew(ctIn *rlwe.Ciphertext, op1 rlwe.Operand) (ctOut *rlwe.Ciphertext) {
	return nil
}

func (de dummyEvaluator) MulAndAdd(ctIn *rlwe.Ciphertext, op1 rlwe.Operand, ctOut *rlwe.Ciphertext) {}

func (de dummyEvaluator) Relinearize(ctIn *rlwe.Ciphertext, ctOut *rlwe.Ciphertext) {
	if de.ctx != nil {
		de.ctx.cDesc.NeedRlk = true
	}

}

func (de dummyEvaluator) RelinearizeNew(ctIn *rlwe.Ciphertext) (ctOut *rlwe.Ciphertext) {
	if de.ctx != nil {
		de.ctx.cDesc.NeedRlk = true
	}
	return nil
}

func (de dummyEvaluator) SwitchKeys(ctIn *rlwe.Ciphertext, switchKey *rlwe.SwitchingKey, ctOut *rlwe.Ciphertext) {
}

func (de dummyEvaluator) EvaluatePoly(input interface{}, pol *bfv.Polynomial) (opOut *rlwe.Ciphertext, err error) {
	return &rlwe.Ciphertext{}, nil
}

func (de dummyEvaluator) EvaluatePolyVector(input interface{}, pols []*bfv.Polynomial, encoder bfv.Encoder, slotsIndex map[int][]int) (opOut *rlwe.Ciphertext, err error) {
	return &rlwe.Ciphertext{}, nil
}

func (de dummyEvaluator) SwitchKeysNew(ctIn *rlwe.Ciphertext, switchkey *rlwe.SwitchingKey) (ctOut *rlwe.Ciphertext) {
	return nil
}

func (de dummyEvaluator) RotateColumnsNew(ctIn *rlwe.Ciphertext, k int) (ctOut *rlwe.Ciphertext) {
	return nil
}

func (de dummyEvaluator) RotateColumns(ctIn *rlwe.Ciphertext, k int, ctOut *rlwe.Ciphertext) {}

func (de dummyEvaluator) RotateRows(ctIn *rlwe.Ciphertext, ctOut *rlwe.Ciphertext) {}

func (de dummyEvaluator) RotateRowsNew(ctIn *rlwe.Ciphertext) (ctOut *rlwe.Ciphertext) {
	return nil
}

func (de dummyEvaluator) InnerSum(ctIn *rlwe.Ciphertext, ctOut *rlwe.Ciphertext) {
	if de.ctx != nil {
		de.ctx.l.Lock()
		defer de.ctx.l.Unlock()
		de.ctx.cDesc.GaloisKeys.AddAll(utils.NewSet(de.ctx.params.GaloisElementsForRowInnerSum()))
	}
}

func (de dummyEvaluator) ShallowCopy() bfv.Evaluator {
	return de
}

func (de dummyEvaluator) WithKey(_ rlwe.EvaluationKey) bfv.Evaluator {
	return de
}

func (de dummyEvaluator) BuffQ() [][]*ring.Poly {
	return nil
}

func (de dummyEvaluator) BuffQMul() [][]*ring.Poly {
	return nil
}

func (de dummyEvaluator) BuffPt() *rlwe.Plaintext {
	return nil
}
