package compute

import (
	"context"
	"fmt"
	"log"

	"golang.org/x/exp/maps"

	"github.com/ChristianMct/helium/circuit"
	"github.com/ChristianMct/helium/protocol"
	"github.com/ChristianMct/helium/session"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he"
	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
	"github.com/tuneinsight/lattigo/v5/schemes/ckks"
)

// KeyOperationRunner is an interface for running key operations.
// It is used by the evaluatorRuntime to run key operations as they are requested by the circuit.
type KeyOperationRunner interface {
	RunKeyOperation(ctx context.Context, sig protocol.Signature) error
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
	cDesc circuit.Descriptor
	//c      circuits.Circuit
	//params bgv.Parameters
	sess        *session.Session
	pkProvider  circuit.PublicKeyProvider
	fheProvider FHEProvider

	// protocols
	protoExec KeyOperationRunner
	*protocol.CompleteMap

	// data
	inputs, ops, outputs map[circuit.OperandLabel]*circuit.FutureOperand

	// eval
	eval he.Evaluator
}

// CircuitInstance (framework-facing) API

func (se *evaluatorRuntime) Init(ctx context.Context, md circuit.Metadata) (err error) {

	se.ops = make(map[circuit.OperandLabel]*circuit.FutureOperand)
	se.inputs = make(map[circuit.OperandLabel]*circuit.FutureOperand)
	for inLabel := range md.InputSet {
		fop := circuit.NewFutureOperand(inLabel)
		se.inputs[inLabel] = fop
		se.ops[inLabel] = fop
	}

	se.outputs = make(map[circuit.OperandLabel]*circuit.FutureOperand)
	for outLabel := range md.OutputSet {
		fop := circuit.NewFutureOperand(outLabel)
		se.outputs[outLabel] = fop
		se.ops[outLabel] = fop
	}

	se.CompleteMap = protocol.NewCompletedProt(maps.Values(md.KeySwitchOps))

	se.eval, err = se.getEvaluatorForCircuit(se.sess.Params, md) // TODO pooled evaluators ?
	if err != nil {
		se.Logf("failed to get evaluator: %v", err)
	}
	return
}

func (se *evaluatorRuntime) getEvaluatorForCircuit(params session.FHEParameters, md circuit.Metadata) (eval he.Evaluator, err error) {

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

func (se *evaluatorRuntime) Eval(ctx context.Context, c circuit.Circuit) (err error) {
	err = c(se)
	if err != nil {
		return err
	}
	return se.Wait()

}

func (se *evaluatorRuntime) IncomingOperand(op circuit.Operand) error {
	fop, has := se.inputs[op.OperandLabel]
	if !has {
		return fmt.Errorf("unexpected input operand: %s", op.OperandLabel)
	}
	fop.Set(op)
	return nil
}

func (se *evaluatorRuntime) GetOperand(_ context.Context, opl circuit.OperandLabel) (op *circuit.Operand, has bool) {
	fop, has := se.ops[opl]
	if !has {
		return
	}
	opg := fop.Get()
	return &opg, true
}

func (se *evaluatorRuntime) GetFutureOperand(_ context.Context, opl circuit.OperandLabel) (op *circuit.FutureOperand, has bool) {
	fop, has := se.ops[opl]
	return fop, has
}

// EvaluationContext (user-facing) API

func (se *evaluatorRuntime) Input(opl circuit.OperandLabel) *circuit.FutureOperand {
	opl = se.getOperandLabelForRuntime(opl)
	op, has := se.inputs[opl]
	if !has {
		panic(fmt.Errorf("non registered input: %s", opl))
	}
	return op
}

func (se *evaluatorRuntime) Load(opl circuit.OperandLabel) *circuit.Operand {
	panic("not supported yet") // TODO implement
}

func (se *evaluatorRuntime) NewOperand(opl circuit.OperandLabel) *circuit.Operand {
	opl = se.getOperandLabelForRuntime(opl)
	return &circuit.Operand{OperandLabel: opl}
}

func (se *evaluatorRuntime) EvalLocal(needRlk bool, galKeys []uint64, f func(he.Evaluator) error) error {
	return f(se.eval)
}

func (se *evaluatorRuntime) keyOpSig(pt protocol.Type, in circuit.Operand, params map[string]string) protocol.Signature {
	params["op"] = string(in.OperandLabel)
	return protocol.Signature{Type: pt, Args: params}
}

func (se *evaluatorRuntime) keyOpExec(sig protocol.Signature, in circuit.Operand) (err error) {

	ctx := session.NewBackgroundContext(se.sess.ID, se.cDesc.CircuitID)

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

func keyOpOutputLabel(inLabel circuit.OperandLabel, sig protocol.Signature) circuit.OperandLabel {
	return circuit.OperandLabel(fmt.Sprintf("%s-%s-out", inLabel, sig.Type))
}

func (se *evaluatorRuntime) getOperandLabelForRuntime(cOpLabel circuit.OperandLabel) circuit.OperandLabel {
	return cOpLabel.ForCircuit(se.cDesc.CircuitID).ForMapping(se.cDesc.NodeMapping)
}

func (se *evaluatorRuntime) DEC(in circuit.Operand, rec session.NodeID, params map[string]string) (err error) {
	var fop *circuit.FutureOperand
	var has bool
	if fop, has = se.ops[in.OperandLabel]; !has {
		fop = circuit.NewFutureOperand(in.OperandLabel)
		se.ops[in.OperandLabel] = fop
	}
	fop.Set(in)

	pparams := maps.Clone(params)
	pparams["target"] = string(se.cDesc.NodeMapping[string(rec)])
	pparams["op"] = string(in.OperandLabel)
	sig := se.keyOpSig(protocol.DEC, in, pparams)
	return se.keyOpExec(sig, in)
}

func (se *evaluatorRuntime) PCKS(in circuit.Operand, rec session.NodeID, params map[string]string) (err error) {
	if _, has := se.ops[in.OperandLabel]; !has {
		fop := circuit.NewFutureOperand(in.OperandLabel)
		fop.Set(in)
		se.ops[in.OperandLabel] = fop
	}
	sig := se.keyOpSig(protocol.PCKS, in, params)
	return se.keyOpExec(sig, in)
}

func (se *evaluatorRuntime) Parameters() session.FHEParameters {
	return se.sess.Params
}

func (se *evaluatorRuntime) Logf(msg string, v ...any) {
	log.Printf("%s | [%s] %s\n", se.cDesc.Evaluator, se.cDesc.CircuitID, fmt.Sprintf(msg, v...))
}
