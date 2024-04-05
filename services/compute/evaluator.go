package compute

import (
	"context"
	"fmt"
	"log"

	"golang.org/x/exp/maps"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/circuits"
	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/session"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he"
	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
	"github.com/tuneinsight/lattigo/v5/schemes/ckks"
)

// KeyOperationRunner is an interface for running key operations.
// It is used by the evaluatorRuntime to run key operations as they are requested by the circuit.
type KeyOperationRunner interface {
	RunKeyOperation(ctx context.Context, sig protocols.Signature) error
}

// evaluatorRuntime is a CircuitRuntime (for the service side) and EvaluationContext (for the circuit cide) implementation for the evaluatorRuntime role.
// This implementation:
//   - resolves all inputs by waiting for the runtime to set them,
//   - evaluates the homomorphic circuit and sets the future operands as it progresses,
//   - runs key operations as they are requested by the circuit, by passing the necessary signatures to the KeyOperationRunner.
//
// The evaluatorRuntime is a stateful object that is created and used for a single evaluation of a single circuit.
// It performs automatic translation of operand labels from the circuit definition to the running instance.
type evaluatorRuntime struct {

	// init
	ctx   context.Context // TODO: check if storing this context this way is a problem
	cDesc circuits.Descriptor
	//c      circuits.Circuit
	//params bgv.Parameters
	sess        *session.Session
	pkProvider  circuits.PublicKeyProvider
	fheProvider FHEProvider

	// protocols
	protoExec KeyOperationRunner
	*protocols.CompleteMap

	// data
	inputs, ops, outputs map[circuits.OperandLabel]*circuits.FutureOperand

	// eval
	eval he.Evaluator
}

// CircuitInstance (framework-facing) API

func (se *evaluatorRuntime) Init(ctx context.Context, md circuits.Metadata) (err error) {

	se.ops = make(map[circuits.OperandLabel]*circuits.FutureOperand)
	se.inputs = make(map[circuits.OperandLabel]*circuits.FutureOperand)
	for inLabel := range md.InputSet {
		fop := circuits.NewFutureOperand(inLabel)
		se.inputs[inLabel] = fop
		se.ops[inLabel] = fop
	}

	se.outputs = make(map[circuits.OperandLabel]*circuits.FutureOperand)
	for outLabel := range md.OutputSet {
		fop := circuits.NewFutureOperand(outLabel)
		se.outputs[outLabel] = fop
		se.ops[outLabel] = fop
	}

	se.CompleteMap = protocols.NewCompletedProt(maps.Values(md.KeySwitchOps))

	se.eval, err = se.getEvaluatorForCircuit(se.sess.Params, md) // TODO pooled evaluators ?
	if err != nil {
		se.Logf("failed to get evaluator: %v", err)
	}
	return
}

func (se *evaluatorRuntime) getEvaluatorForCircuit(params session.FHEParameters, md circuits.Metadata) (eval he.Evaluator, err error) {

	var rlk *rlwe.RelinearizationKey
	if md.NeedRlk {
		rlk, err = se.pkProvider.GetRelinearizationKey(se.ctx)
		if err != nil {
			return nil, err
		}
	}
	gks := make([]*rlwe.GaloisKey, 0, len(md.GaloisKeys))
	for galEl := range md.GaloisKeys {
		gk, err := se.pkProvider.GetGaloisKey(se.ctx, galEl)
		if err != nil {
			return nil, err
		}
		gks = append(gks, gk)
	}
	ks := rlwe.NewMemEvaluationKeySet(rlk, gks...)

	switch pp := params.(type) {
	case bgv.Parameters:
		eval = bgv.NewEvaluator(pp, ks)
	case ckks.Parameters:
		eval = ckks.NewEvaluator(pp, ks)
	}

	return eval, nil

}

func (se *evaluatorRuntime) Eval(ctx context.Context, c circuits.Circuit) (err error) {
	err = c(se)
	if err != nil {
		return err
	}
	return se.Wait()

}

func (se *evaluatorRuntime) IncomingOperand(op circuits.Operand) error {
	fop, has := se.inputs[op.OperandLabel]
	if !has {
		return fmt.Errorf("unexpected input operand: %s", op.OperandLabel)
	}
	fop.Set(op)
	return nil
}

func (se *evaluatorRuntime) GetOperand(_ context.Context, opl circuits.OperandLabel) (op *circuits.Operand, has bool) {
	fop, has := se.ops[opl]
	if !has {
		return
	}
	opg := fop.Get()
	return &opg, true
}

func (se *evaluatorRuntime) GetFutureOperand(_ context.Context, opl circuits.OperandLabel) (op *circuits.FutureOperand, has bool) {
	fop, has := se.ops[opl]
	return fop, has
}

// EvaluationContext (user-facing) API

func (se *evaluatorRuntime) Input(opl circuits.OperandLabel) *circuits.FutureOperand {
	opl = se.getOperandLabelForRuntime(opl)
	op, has := se.inputs[opl]
	if !has {
		panic(fmt.Errorf("non registered input: %s", opl))
	}
	return op
}

func (se *evaluatorRuntime) Load(opl circuits.OperandLabel) *circuits.Operand {
	panic("not supported yet") // TODO implement
}

func (se *evaluatorRuntime) NewOperand(opl circuits.OperandLabel) *circuits.Operand {
	opl = se.getOperandLabelForRuntime(opl)
	return &circuits.Operand{OperandLabel: opl}
}

func (se *evaluatorRuntime) EvalLocal(needRlk bool, galKeys []uint64, f func(he.Evaluator) error) error {
	return f(se.eval)
}

func (se *evaluatorRuntime) keyOpSig(pt protocols.Type, in circuits.Operand, params map[string]string) protocols.Signature {
	params["op"] = string(in.OperandLabel)
	return protocols.Signature{Type: pt, Args: params}
}

func (se *evaluatorRuntime) keyOpExec(sig protocols.Signature, in circuits.Operand) (err error) {

	ctx := helium.NewBackgroundContext(se.sess.ID, se.cDesc.CircuitID)

	if err := se.protoExec.RunKeyOperation(ctx, sig); err != nil {
		return err
	}

	outLabel := keyOpOutputLabel(in.OperandLabel, sig)
	if outfop, isOutput := se.outputs[outLabel]; isOutput {
		outfop.Get() // waits for keyop to complete
		return
	}
	return fmt.Errorf("key op should have an output future operand for %s", outLabel)
}

func keyOpOutputLabel(inLabel circuits.OperandLabel, sig protocols.Signature) circuits.OperandLabel {
	return circuits.OperandLabel(fmt.Sprintf("%s-%s-out", inLabel, sig.Type))
}

func (se *evaluatorRuntime) getOperandLabelForRuntime(cOpLabel circuits.OperandLabel) circuits.OperandLabel {
	return cOpLabel.ForCircuit(se.cDesc.CircuitID).ForMapping(se.cDesc.NodeMapping)
}

func (se *evaluatorRuntime) DEC(in circuits.Operand, rec helium.NodeID, params map[string]string) (err error) {
	var fop *circuits.FutureOperand
	var has bool
	if fop, has = se.ops[in.OperandLabel]; !has {
		fop = circuits.NewFutureOperand(in.OperandLabel)
		se.ops[in.OperandLabel] = fop
	}
	fop.Set(in)

	pparams := maps.Clone(params)
	pparams["target"] = string(se.cDesc.NodeMapping[string(rec)])
	pparams["op"] = string(in.OperandLabel)
	sig := se.keyOpSig(protocols.DEC, in, pparams)
	return se.keyOpExec(sig, in)
}

func (se *evaluatorRuntime) PCKS(in circuits.Operand, rec helium.NodeID, params map[string]string) (err error) {
	if _, has := se.ops[in.OperandLabel]; !has {
		fop := circuits.NewFutureOperand(in.OperandLabel)
		fop.Set(in)
		se.ops[in.OperandLabel] = fop
	}
	sig := se.keyOpSig(protocols.PCKS, in, params)
	return se.keyOpExec(sig, in)
}

func (se *evaluatorRuntime) Parameters() session.FHEParameters {
	return se.sess.Params
}

func (se *evaluatorRuntime) Logf(msg string, v ...any) {
	log.Printf("%s | [%s] %s\n", se.cDesc.Evaluator, se.cDesc.CircuitID, fmt.Sprintf(msg, v...))
}
