package circuits

import (
	"encoding/json"
	"fmt"
	"maps"
	"sync"

	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/sessions"
	"github.com/ChristianMct/helium/utils"
	"github.com/tuneinsight/lattigo/v5/he"
)

// Parse parses a circuit and returns its metadata.
// The parsing is done by symbolic execution of the circuit.
func Parse(c Circuit, cd Descriptor, params sessions.FHEParameters) (*Metadata, error) {
	dummyCtx := newCircuitParserCtx(cd, params)
	if err := c(dummyCtx); err != nil {
		return nil, fmt.Errorf("error while parsing circuit: %w", err)
	}
	return &dummyCtx.md, nil
}

type circuitParserContext struct {
	//dummyEvaluator
	cd     Descriptor
	md     Metadata
	SubCtx map[sessions.CircuitID]*circuitParserContext
	params sessions.FHEParameters
	l      sync.Mutex
}

func newCircuitParserCtx(cd Descriptor, params sessions.FHEParameters) *circuitParserContext {
	cpc := &circuitParserContext{
		cd: cd,
		md: Metadata{
			Descriptor:   cd,
			InputSet:     utils.NewEmptySet[OperandLabel](),
			Ops:          utils.NewEmptySet[OperandLabel](),
			OutputSet:    utils.NewEmptySet[OperandLabel](),
			InputsFor:    make(map[sessions.NodeID]utils.Set[OperandLabel]),
			OutputsFor:   make(map[sessions.NodeID]utils.Set[OperandLabel]),
			KeySwitchOps: make(map[string]protocols.Signature),
			GaloisKeys:   make(utils.Set[uint64]),
		},
		SubCtx: make(map[sessions.CircuitID]*circuitParserContext, 0),
		params: params,
	}
	//cpc.dummyEvaluator.ctx = cpc
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

func (e *circuitParserContext) NewOperand(opl OperandLabel) *Operand {
	e.l.Lock()
	defer e.l.Unlock()
	e.md.Ops.Add(opl.ForCircuit(e.cd.CircuitID).ForMapping(e.cd.NodeMapping))
	return &Operand{OperandLabel: opl}
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

func (e *circuitParserContext) Output(out Operand, to sessions.NodeID) {
	e.l.Lock()
	defer e.l.Unlock()
	e.output(out, to)
}

func (e *circuitParserContext) output(out Operand, to sessions.NodeID) {
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

func (e *circuitParserContext) DEC(in Operand, rec sessions.NodeID, params map[string]string) (err error) {
	e.Set(in)
	e.l.Lock()
	defer e.l.Unlock()

	if argRec, has := params["target"]; has && sessions.NodeID(argRec) != rec {
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

func (e *circuitParserContext) PCKS(in Operand, rec sessions.NodeID, params map[string]string) (err error) {
	e.Set(in)
	e.l.Lock()
	defer e.l.Unlock()

	if argRec, has := params["target"]; has && sessions.NodeID(argRec) != rec {
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

func (e *circuitParserContext) Circuit() Descriptor {
	e.l.Lock()
	defer e.l.Unlock()
	return e.cd.Clone()
}

func (e *circuitParserContext) Parameters() sessions.FHEParameters {
	e.l.Lock()
	defer e.l.Unlock()
	return e.params
}

func (e *circuitParserContext) EvalLocal(needRlk bool, galKeys []uint64, f func(he.Evaluator) error) error {
	e.l.Lock()
	defer e.l.Unlock()
	e.md.NeedRlk = needRlk
	e.md.GaloisKeys.AddAll(utils.NewSet(galKeys))
	return nil
}

func (e *circuitParserContext) Logf(format string, args ...interface{}) {
}
