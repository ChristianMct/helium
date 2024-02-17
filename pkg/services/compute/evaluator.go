package compute

import (
	"context"
	"fmt"
	"maps"

	"github.com/ldsec/helium/pkg/circuits"
	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/protocols"
	"github.com/tuneinsight/lattigo/v4/bgv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe/ringqp"
)

type ProtocolExecutor interface {
	RunKeyOperation(ctx context.Context, sig protocols.Signature, in circuits.Operand, out *circuits.FutureOperand) error
}

type fheEvaluator struct {
	*bgv.Evaluator
}

type evaluator struct {
	cDesc  circuits.Descriptor
	c      circuits.Circuit
	params bgv.Parameters

	// keys
	pubKeyBackend PublicKeyBackend

	// protocols
	protoExec ProtocolExecutor

	// data

	inputs, ops, outputs map[circuits.OperandLabel]*circuits.FutureOperand
	ctbk                 OperandBackend

	// eval
	*fheEvaluator
}

func newEvaluator(c circuits.Circuit, cd circuits.Descriptor, params bgv.Parameters, pkbk PublicKeyBackend, pe ProtocolExecutor) (ev *evaluator, err error) {
	ev = new(evaluator)
	ev.c = c
	ev.cDesc = cd
	ev.pubKeyBackend = pkbk
	ev.protoExec = pe
	ev.params = params

	ci, err := circuits.Parse(c, cd, params)
	if err != nil {
		return nil, err
	}

	ev.inputs = make(map[circuits.OperandLabel]*circuits.FutureOperand)
	for inLabel := range ci.InputSet {
		ev.inputs[inLabel] = circuits.NewFutureOperand(inLabel)
	}

	ev.outputs = make(map[circuits.OperandLabel]*circuits.FutureOperand)
	for outLabel := range ci.OutputSet {
		ev.outputs[outLabel] = circuits.NewFutureOperand(outLabel)
	}

	ev.fheEvaluator, err = newLattigoEvaluator(*ci, params, pkbk)
	if err != nil {
		return nil, err
	}

	return ev, nil
}

func newLattigoEvaluator(ci circuits.Info, params bgv.Parameters, pkbk PublicKeyBackend) (eval *fheEvaluator, err error) {
	rlk := new(rlwe.RelinearizationKey)
	if ci.NeedRlk {
		rlk, err = pkbk.GetRelinearizationKey()
		if err != nil {
			return nil, err
		}
	}

	gks := make([]*rlwe.GaloisKey, 0, len(ci.GaloisKeys))
	for galEl := range ci.GaloisKeys {
		var err error
		gk, err := pkbk.GetGaloisKey(galEl)
		if err != nil {
			return nil, err
		}
		gks = append(gks, gk)
	}

	//rtks := rlwe.NewRotationKeySet(se.params.Parameters, se.cDesc.GaloisKeys.Elements())
	evk := rlwe.NewMemEvaluationKeySet(rlk, gks...)
	eval = &fheEvaluator{bgv.NewEvaluator(params, evk)}
	return eval, nil
}

// CircuitInstance (framework-facing) API
func (se *evaluator) IncomingOperand(op circuits.Operand) error {
	fop, has := se.inputs[op.OperandLabel]
	if !has {
		return fmt.Errorf("unexpected input operand: %s", op.OperandLabel)
	}
	fop.Set(op)
	return nil
}

func (se *evaluator) GetOperand(opl circuits.OperandLabel) (op *circuits.Operand, err error) {
	fop, has := se.ops[opl]
	if !has {
		return nil, fmt.Errorf("no operand with label %s in circuit", opl)
	}
	opg := fop.Get()
	return &opg, nil
}

// EvaluationContext (user-facing) API

func (se *evaluator) Input(opl circuits.OperandLabel) circuits.FutureOperand {
	return *se.inputs[opl]
}

func (se *evaluator) Load(opl circuits.OperandLabel) circuits.Operand {
	op, err := se.ctbk.Get(opl)
	if err != nil {
		panic(err)
	}
	return *op
}

func (se *evaluator) Set(op circuits.Operand) {
	se.ctbk.Set(op)
}

func (se *evaluator) keyOpSig(pt protocols.Type, in circuits.Operand, params map[string]string) protocols.Signature {
	pparams := maps.Clone(params)
	pparams["op"] = string(in.OperandLabel.ForCircuit(se.cDesc.ID).ForMapping(se.cDesc.InputParties))
	return protocols.Signature{Type: pt, Args: params}
}

func (se *evaluator) keyOpExec(sig protocols.Signature, in circuits.Operand) (out *circuits.FutureOperand, err error) {
	outLabel := keyOpOutputLabel(in.OperandLabel, sig)
	var isOutput bool
	if out, isOutput = se.outputs[outLabel]; !isOutput {
		out = circuits.NewFutureOperand(outLabel)
	}

	go func() {
		err := se.protoExec.RunKeyOperation(context.Background(), sig, in, out)
		if err != nil {
			panic(err)
		}
	}()
	return out, nil
}

func keyOpOutputLabel(inLabel circuits.OperandLabel, sig protocols.Signature) circuits.OperandLabel {
	return circuits.OperandLabel(fmt.Sprintf("%s-%s-out", inLabel, sig.Type))
}

func (se *evaluator) DEC(in circuits.Operand, params map[string]string) (out *circuits.FutureOperand, err error) {
	sig := se.keyOpSig(protocols.DEC, in, params)
	return se.keyOpExec(sig, in)
}

func (se *evaluator) PCKS(in circuits.Operand, params map[string]string) (out *circuits.FutureOperand, err error) {
	sig := se.keyOpSig(protocols.PCKS, in, params)
	return se.keyOpExec(sig, in)
}

func (se *evaluator) Output(op circuits.Operand, nid pkg.NodeID) {
	se.outputs[op.OperandLabel].Set(op)
}

func (se *evaluator) Parameters() bgv.Parameters {
	return se.params
}

func (se *evaluator) NewEvaluator() circuits.Evaluator {
	return &fheEvaluator{se.fheEvaluator.ShallowCopy()}
}

func (ew *fheEvaluator) NewDecompQPBuffer() []ringqp.Poly {
	params := ew.Parameters()
	decompRNS := params.DecompRNS(params.MaxLevelQ(), 0)
	ringQP := params.RingQP()
	buffDecompQP := make([]ringqp.Poly, decompRNS)
	for i := 0; i < decompRNS; i++ {
		buffDecompQP[i] = ringQP.NewPoly()
	}
	return buffDecompQP
}
