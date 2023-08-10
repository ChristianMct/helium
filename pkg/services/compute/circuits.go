package compute

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/protocols"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v4/bgv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

type Evaluator interface {
	Add(op0 *rlwe.Ciphertext, op1 interface{}, opOut *rlwe.Ciphertext) (err error)
	Sub(op0 *rlwe.Ciphertext, op1 interface{}, opOut *rlwe.Ciphertext) (err error)
	Mul(op0 *rlwe.Ciphertext, op1 interface{}, opOut *rlwe.Ciphertext) (err error)
	MulNew(op0 *rlwe.Ciphertext, op1 interface{}) (opOut *rlwe.Ciphertext, err error)
	MulRelin(op0 *rlwe.Ciphertext, op1 interface{}, opOut *rlwe.Ciphertext) (err error)
	MulRelinNew(op0 *rlwe.Ciphertext, op1 interface{}) (opOut *rlwe.Ciphertext, err error)
	MulThenAdd(op0 *rlwe.Ciphertext, op1 interface{}, opOut *rlwe.Ciphertext) (err error)
	Relinearize(op0, op1 *rlwe.Ciphertext) (err error)
	Rescale(op0, op1 *rlwe.Ciphertext) (err error)
	InnerSum(ctIn *rlwe.Ciphertext, batchSize, n int, opOut *rlwe.Ciphertext) (err error)
}

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
	Parameters() bgv.Parameters

	NewEvaluator() Evaluator

	EvalWithKey(evk rlwe.EvaluationKeySet) Evaluator

	Evaluator
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
	params      bgv.Parameters
	nodeMapping map[string]pkg.NodeID
	l           sync.Mutex
}

func newCircuitParserCtx(cid pkg.CircuitID, params bgv.Parameters, nodeMapping map[string]pkg.NodeID) *circuitParserContext {
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

func (e *circuitParserContext) Parameters() bgv.Parameters {
	e.l.Lock()
	defer e.l.Unlock()
	return e.params
}

func (e *circuitParserContext) MulRelin(op0 *rlwe.Ciphertext, op1 interface{}, opOut *rlwe.Ciphertext) (err error) {
	e.l.Lock()
	defer e.l.Unlock()
	e.ctx.cDesc.NeedRlk = true
	return nil
}

func (e *circuitParserContext) MulRelinNew(op0 *rlwe.Ciphertext, op1 interface{}) (opOut *rlwe.Ciphertext, err error) {
	e.l.Lock()
	defer e.l.Unlock()
	e.ctx.cDesc.NeedRlk = true
	return nil, nil
}

func (e *circuitParserContext) Relinearize(op0 *rlwe.Ciphertext, op1 *rlwe.Ciphertext) (err error) {
	e.l.Lock()
	defer e.l.Unlock()
	e.ctx.cDesc.NeedRlk = true
	return nil
}

func (e *circuitParserContext) InnerSum(ctIn *rlwe.Ciphertext, batchSize int, n int, opOut *rlwe.Ciphertext) (err error) {
	e.l.Lock()
	defer e.l.Unlock()
	e.ctx.cDesc.GaloisKeys.AddAll(utils.NewSet(e.ctx.params.GaloisElementsForInnerSum(batchSize, n)))
	return nil
}

type dummyEvaluator struct{ ctx *circuitParserContext }

func (de *dummyEvaluator) Add(op0 *rlwe.Ciphertext, op1 interface{}, opOut *rlwe.Ciphertext) (err error) {
	return nil
}

func (de *dummyEvaluator) Sub(op0 *rlwe.Ciphertext, op1 interface{}, opOut *rlwe.Ciphertext) (err error) {
	return nil
}

func (de *dummyEvaluator) Mul(op0 *rlwe.Ciphertext, op1 interface{}, opOut *rlwe.Ciphertext) (err error) {
	return nil
}

func (de *dummyEvaluator) MulNew(op0 *rlwe.Ciphertext, op1 interface{}) (opOut *rlwe.Ciphertext, err error) {
	return nil, nil
}

func (de *dummyEvaluator) MulRelin(op0 *rlwe.Ciphertext, op1 interface{}, opOut *rlwe.Ciphertext) (err error) {
	return nil
}

func (de *dummyEvaluator) MulRelinNew(op0 *rlwe.Ciphertext, op1 interface{}) (opOut *rlwe.Ciphertext, err error) {
	return nil, nil
}

func (de *dummyEvaluator) Relinearize(op0 *rlwe.Ciphertext, op1 *rlwe.Ciphertext) (err error) {
	return nil
}

func (de *dummyEvaluator) MulThenAdd(op0 *rlwe.Ciphertext, op1 interface{}, opOut *rlwe.Ciphertext) (err error) {
	return nil
}

func (de *dummyEvaluator) Rescale(op0 *rlwe.Ciphertext, op1 *rlwe.Ciphertext) (err error) {
	return nil
}

func (de *dummyEvaluator) InnerSum(ctIn *rlwe.Ciphertext, batchSize int, n int, opOut *rlwe.Ciphertext) (err error) {
	return nil
}

func (de *dummyEvaluator) NewEvaluator() Evaluator {
	return de
}

func (de *dummyEvaluator) EvalWithKey(_ rlwe.EvaluationKeySet) Evaluator {
	return de
}
