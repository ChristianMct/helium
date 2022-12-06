package compute

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"sync"

	pkg "github.com/ldsec/helium/pkg/session"
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
	Output(pkg.Operand)

	// CKS runs a CKS protocol over the provided operand within the context.
	CKS(id pkg.ProtocolID, in pkg.Operand, params map[string]interface{}) (out pkg.Operand, err error)

	// PCKS runs a PCKS protocol over the provided operand within the context.
	PCKS(id pkg.ProtocolID, in pkg.Operand, params map[string]interface{}) (out pkg.Operand, err error)

	// SubCircuit evaluates a sub-circuit within the context.
	SubCircuit(pkg.CircuitID, Circuit) (EvaluationContext, error)

	// Parameters returns the encryption parameters for the circuit.
	Parameters() bfv.Parameters

	bfv.Evaluator
}

// Circuit is a type for representing circuits, which are go functions interacting with
// a provided evaluation context.
type Circuit func(EvaluationContext) error

// It seems that a central piece of the orchestration could be a good
// URL scheme for locating/designating ciphertexts
type URL url.URL

func ParseURL(s string) (*URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	return (*URL)(u), nil
}

func NewURL(s string) *URL {
	url, err := ParseURL(s)
	if err != nil {
		panic(err)
	}
	return url
}

func (u *URL) IsSessionWide() bool {
	return u.Host == ""
}

func (u *URL) CiphertextBaseID() pkg.CiphertextID {
	return pkg.CiphertextID(path.Base(u.Path))
}

func (u *URL) CiphertextID() pkg.CiphertextID {
	return pkg.CiphertextID(u.String())
}

func (u *URL) NodeID() pkg.NodeID {
	return pkg.NodeID(u.Host)
}

func (u *URL) String() string {
	return (*url.URL)(u).String()
}

type CircuitDescription struct {
	InputSet, Ops, OutputSet utils.Set[pkg.OperandLabel]
	CKSs, PCKSs              map[pkg.ProtocolID]map[string]interface{}
	NeedRlk                  bool
}

type circuitParserContext struct {
	dummyEvaluator
	cDesc       CircuitDescription
	circId      pkg.CircuitID
	SubCtx      map[pkg.CircuitID]*circuitParserContext
	params      bfv.Parameters
	nodeMapping map[string]pkg.NodeID
	l           sync.Mutex
}

func newCircuitParserCtx(id pkg.CircuitID, params bfv.Parameters, nodeMapping map[string]pkg.NodeID) *circuitParserContext {
	return &circuitParserContext{circId: id,
		cDesc: CircuitDescription{
			InputSet:  utils.NewEmptySet[pkg.OperandLabel](),
			Ops:       utils.NewEmptySet[pkg.OperandLabel](),
			OutputSet: utils.NewEmptySet[pkg.OperandLabel](),
			CKSs:      make(map[pkg.ProtocolID]map[string]interface{}),
			PCKSs:     make(map[pkg.ProtocolID]map[string]interface{}),
		},
		SubCtx:      make(map[pkg.CircuitID]*circuitParserContext, 0),
		params:      params,
		nodeMapping: nodeMapping,
	}
}

func (e *circuitParserContext) CircuitDescription() CircuitDescription {
	return e.cDesc
}

func (e *circuitParserContext) String() string {
	e.l.Lock()
	defer e.l.Unlock()
	//return fmt.Sprintf("Inputs: %s\nOutputs: %s\n SubCtx: %v\n", e.inputSet, e.outputSet, e.subCtx)
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
	//fmt.Println("inputting", in)
	e.cDesc.InputSet.Add(in.ForCircuit(e.circId).ForMapping(e.nodeMapping))
	return pkg.Operand{OperandLabel: in}
}

func (e *circuitParserContext) Set(op pkg.Operand) {
	e.l.Lock()
	defer e.l.Unlock()
	opl := op.OperandLabel.ForCircuit(e.circId).ForMapping(e.nodeMapping)
	//fmt.Println("setting", opl)
	e.cDesc.Ops.Add(opl)
}

func (e *circuitParserContext) Get(opl pkg.OperandLabel) pkg.Operand {
	e.l.Lock()
	defer e.l.Unlock()
	//fmt.Println("getting", opl)
	e.cDesc.Ops.Add(opl.ForCircuit(e.circId).ForMapping(e.nodeMapping))
	return pkg.Operand{OperandLabel: opl}
}

func (e *circuitParserContext) Output(out pkg.Operand) {
	e.l.Lock()
	defer e.l.Unlock()
	opl := out.OperandLabel.ForCircuit(e.circId).ForMapping(e.nodeMapping)
	//fmt.Println("outputting", opl)
	e.cDesc.OutputSet.Add(opl)
	e.cDesc.Ops.Add(opl)
}

func (e *circuitParserContext) SubCircuit(id pkg.CircuitID, cd Circuit) (EvaluationContext, error) {
	e.l.Lock()
	defer e.l.Unlock()
	//fmt.Println("executing sub circuit", id)
	subCtx := newCircuitParserCtx(pkg.CircuitID(fmt.Sprintf("%s/%s", e.circId, id)), e.params, e.nodeMapping)
	e.SubCtx[id] = subCtx
	err := cd(subCtx)
	return subCtx, err
}

func (e *circuitParserContext) CKS(id pkg.ProtocolID, in pkg.Operand, params map[string]interface{}) (out pkg.Operand, err error) {
	e.Set(in)
	e.l.Lock()
	defer e.l.Unlock()
	if _, exists := e.cDesc.CKSs[id]; exists {
		panic("CKS with id exists")
	}

	target, hasTarget := params["target"]
	if !hasTarget {
		return pkg.Operand{}, fmt.Errorf("CKS parameter should have a target")
	}

	targetStr, isString := target.(string)
	if !isString {
		return pkg.Operand{}, fmt.Errorf("CKS parameter should have target of string type")
	}

	if e.nodeMapping != nil {
		params["target"] = e.nodeMapping[targetStr]
	}

	e.cDesc.CKSs[id] = params
	return pkg.Operand{OperandLabel: pkg.OperandLabel(fmt.Sprintf("//%s/%s-out-0", targetStr, id))}, nil
}

func (e *circuitParserContext) PCKS(id pkg.ProtocolID, in pkg.Operand, params map[string]interface{}) (out pkg.Operand, err error) {
	e.Set(in)
	e.l.Lock()
	defer e.l.Unlock()
	if _, exists := e.cDesc.PCKSs[id]; exists {
		panic("PCKS with id exists")
	}

	target, hasTarget := params["target"]
	if !hasTarget {
		return pkg.Operand{}, fmt.Errorf("PCKS parameter should have a target")
	}

	targetStr, isString := target.(string)
	if !isString {
		return pkg.Operand{}, fmt.Errorf("PCKS parameter should have target of string type")
	}

	if e.nodeMapping != nil {
		params["target"] = e.nodeMapping[targetStr]
	}

	e.cDesc.PCKSs[id] = params
	return pkg.Operand{OperandLabel: pkg.OperandLabel(fmt.Sprintf("//%s/%s-out-0", targetStr, id))}, nil
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

type dummyEvaluator struct{}

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

func (de dummyEvaluator) Relinearize(ctIn *rlwe.Ciphertext, ctOut *rlwe.Ciphertext) {}

func (de dummyEvaluator) RelinearizeNew(ctIn *rlwe.Ciphertext) (ctOut *rlwe.Ciphertext) {
	return nil
}

func (de dummyEvaluator) SwitchKeys(ctIn *rlwe.Ciphertext, switchKey *rlwe.SwitchingKey, ctOut *rlwe.Ciphertext) {
}

func (de dummyEvaluator) EvaluatePoly(input interface{}, pol *bfv.Polynomial) (opOut *rlwe.Ciphertext, err error) {
	return nil, nil
}

func (de dummyEvaluator) EvaluatePolyVector(input interface{}, pols []*bfv.Polynomial, encoder bfv.Encoder, slotsIndex map[int][]int) (opOut *rlwe.Ciphertext, err error) {
	return nil, nil
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

func (de dummyEvaluator) InnerSum(ctIn *rlwe.Ciphertext, ctOut *rlwe.Ciphertext) {}

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
