package circuits

import (
	"encoding/json"
	"fmt"
	"maps"
	"sync"

	"github.com/ldsec/helium/pkg"
	"github.com/ldsec/helium/pkg/protocols"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v4/bgv"
	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe/ringqp"
)

// Parse parses a circuit and returns its metadata.
// The parsing is done by symbolic execution of the circuit.
func Parse(c Circuit, cd Descriptor, params bgv.Parameters) (*Metadata, error) {
	dummyCtx := newCircuitParserCtx(cd, params)
	if err := c(dummyCtx); err != nil {
		return nil, fmt.Errorf("error while parsing circuit: %w", err)
	}
	return &dummyCtx.md, nil
}

type circuitParserContext struct {
	dummyEvaluator
	cd     Descriptor
	md     Metadata
	SubCtx map[pkg.CircuitID]*circuitParserContext
	params bgv.Parameters
	l      sync.Mutex
}

func newCircuitParserCtx(cd Descriptor, params bgv.Parameters) *circuitParserContext {
	cpc := &circuitParserContext{
		cd: cd,
		md: Metadata{
			Descriptor:   cd,
			InputSet:     utils.NewEmptySet[OperandLabel](),
			Ops:          utils.NewEmptySet[OperandLabel](),
			OutputSet:    utils.NewEmptySet[OperandLabel](),
			InputsFor:    make(map[pkg.NodeID]utils.Set[OperandLabel]),
			OutputsFor:   make(map[pkg.NodeID]utils.Set[OperandLabel]),
			KeySwitchOps: make(map[string]protocols.Signature),
			GaloisKeys:   make(utils.Set[uint64]),
		},
		SubCtx: make(map[pkg.CircuitID]*circuitParserContext, 0),
		params: params,
	}
	cpc.dummyEvaluator.ctx = cpc
	return cpc
}

func (e *circuitParserContext) CircuitMetadata() Metadata {
	return e.md
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

func (e *circuitParserContext) Input(in OperandLabel) *FutureOperand {
	e.l.Lock()
	defer e.l.Unlock()
	opl := in.ForCircuit(e.cd.CircuitID).ForMapping(e.cd.NodeMapping)
	e.md.InputSet.Add(opl)

	from := opl.NodeID()
	inset, exists := e.md.InputsFor[from]
	if !exists {
		inset = utils.NewEmptySet[OperandLabel]()
		e.md.InputsFor[from] = inset
	}
	inset.Add(opl)

	c := make(chan struct{})
	close(c)
	return &FutureOperand{Operand: Operand{OperandLabel: in}, c: c}
}

func (e *circuitParserContext) Load(in OperandLabel) *Operand {
	return &Operand{OperandLabel: in} // TODO: collect ciphertext dependencies
}

func (e *circuitParserContext) NewOperand(opl OperandLabel) Operand {
	e.l.Lock()
	defer e.l.Unlock()
	e.md.Ops.Add(opl.ForCircuit(e.cd.CircuitID).ForMapping(e.cd.NodeMapping))
	return Operand{OperandLabel: opl}
}

func (e *circuitParserContext) Set(op Operand) {
	e.l.Lock()
	defer e.l.Unlock()
	opl := op.OperandLabel.ForCircuit(e.cd.CircuitID).ForMapping(e.cd.NodeMapping)
	e.md.Ops.Add(opl)
}

func (e *circuitParserContext) Get(opl OperandLabel) Operand {
	e.l.Lock()
	defer e.l.Unlock()
	e.md.Ops.Add(opl.ForCircuit(e.cd.CircuitID).ForMapping(e.cd.NodeMapping))
	return Operand{OperandLabel: opl}
}

func (e *circuitParserContext) Output(out Operand, to pkg.NodeID) {
	e.l.Lock()
	defer e.l.Unlock()
	e.output(out, to)
}

func (e *circuitParserContext) output(out Operand, to pkg.NodeID) {
	opl := out.OperandLabel.ForCircuit(e.cd.CircuitID).ForMapping(e.cd.NodeMapping)
	e.md.OutputSet.Add(opl)
	e.md.Ops.Add(opl)

	tonid, has := e.cd.NodeMapping[string(to)]
	if !has {
		panic(fmt.Errorf("unknown node mapping for output reciever: %s", to))
	}

	outset, exists := e.md.OutputsFor[tonid]
	if !exists {
		outset = utils.NewEmptySet[OperandLabel]()
		e.md.OutputsFor[tonid] = outset
	}
	outset.Add(opl)
}

func (e *circuitParserContext) registerKeyOps(sig protocols.Signature) error {

	target, hasTarget := sig.Args["target"]
	if !hasTarget {
		return fmt.Errorf("protocol parameter should have a target")
	}

	nid, has := e.cd.NodeMapping[target]
	if !has {
		panic(fmt.Errorf("unkown mapping to node for key op target: %s", target))
	}
	sig.Args["target"] = string(nid)

	if _, exists := e.md.KeySwitchOps[sig.String()]; exists {
		return fmt.Errorf("protocol with id %s exists", sig.String())
	}

	e.md.KeySwitchOps[sig.String()] = sig
	return nil
}

func GetProtocolSignature(t protocols.Type, in OperandLabel, params map[string]string) (pd protocols.Signature) {
	parm := make(map[string]string, len(params))
	for k, v := range params {
		parm[k] = v
	}
	parm["op"] = string(in)
	return protocols.Signature{Type: t, Args: parm}
}

func (e *circuitParserContext) DEC(in Operand, rec pkg.NodeID, params map[string]string) (err error) {
	e.Set(in)
	e.l.Lock()
	defer e.l.Unlock()

	if argRec, has := params["target"]; has && pkg.NodeID(argRec) != rec {
		return fmt.Errorf("if specified, the target argument must match rec")
	}

	pparams := maps.Clone(params)
	pparams["target"] = string(rec)

	pd := GetProtocolSignature(protocols.DEC, in.OperandLabel.ForCircuit(e.cd.CircuitID).ForMapping(e.cd.NodeMapping), pparams)
	if err = e.registerKeyOps(pd); err != nil {
		return err
	}
	opOut := Operand{OperandLabel: OperandLabel(fmt.Sprintf("%s-%s-out", in.OperandLabel, pd.Type))}
	e.output(opOut, rec)
	return nil
}

func (e *circuitParserContext) PCKS(in Operand, rec pkg.NodeID, params map[string]string) (err error) {
	e.Set(in)
	e.l.Lock()
	defer e.l.Unlock()

	if argRec, has := params["target"]; has && pkg.NodeID(argRec) != rec {
		return fmt.Errorf("if specified, the target argument must match rec")
	}

	pparams := maps.Clone(params)
	pparams["target"] = string(rec)

	pd := GetProtocolSignature(protocols.PCKS, in.OperandLabel.ForCircuit(e.cd.CircuitID).ForMapping(e.cd.NodeMapping), params)
	if err = e.registerKeyOps(pd); err != nil {
		panic(err)
	}
	opOut := Operand{OperandLabel: OperandLabel(fmt.Sprintf("%s-%s-out", in.OperandLabel, pd.Type))}
	e.output(opOut, rec)
	return nil
}

func (e *circuitParserContext) Parameters() bgv.Parameters {
	e.l.Lock()
	defer e.l.Unlock()
	return e.params
}

func (e *circuitParserContext) MulRelin(op0 *rlwe.Ciphertext, op1 interface{}, opOut *rlwe.Ciphertext) (err error) {
	e.l.Lock()
	defer e.l.Unlock()
	e.md.NeedRlk = true
	return nil
}

func (e *circuitParserContext) MulRelinNew(op0 *rlwe.Ciphertext, op1 interface{}) (opOut *rlwe.Ciphertext, err error) {
	e.l.Lock()
	defer e.l.Unlock()
	e.md.NeedRlk = true
	return nil, nil
}

func (e *circuitParserContext) Relinearize(op0 *rlwe.Ciphertext, op1 *rlwe.Ciphertext) (err error) {
	e.l.Lock()
	defer e.l.Unlock()
	e.md.NeedRlk = true
	return nil
}

func (e *circuitParserContext) InnerSum(ctIn *rlwe.Ciphertext, batchSize int, n int, opOut *rlwe.Ciphertext) (err error) {
	e.l.Lock()
	defer e.l.Unlock()
	e.md.GaloisKeys.AddAll(utils.NewSet(e.ctx.params.GaloisElementsForInnerSum(batchSize, n)))
	return nil
}

func (e *circuitParserContext) AutomorphismHoisted(level int, ctIn *rlwe.Ciphertext, c1DecompQP []ringqp.Poly, galEl uint64, opOut *rlwe.Ciphertext) (err error) {
	e.l.Lock()
	defer e.l.Unlock()
	e.md.GaloisKeys.Add(galEl)
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

func (de *dummyEvaluator) NewDecompQPBuffer() []ringqp.Poly {
	return nil
}

func (de *dummyEvaluator) AutomorphismHoisted(level int, ctIn *rlwe.Ciphertext, c1DecompQP []ringqp.Poly, galEl uint64, opOut *rlwe.Ciphertext) (err error) {
	return nil
}

func (de *dummyEvaluator) DecomposeNTT(levelQ, levelP, nbPi int, c2 ring.Poly, c2IsNTT bool, decompQP []ringqp.Poly) {

}
