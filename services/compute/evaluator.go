package compute

import (
	"context"
	"fmt"
	"log"

	"golang.org/x/exp/maps"

	"github.com/ChristianMct/helium/circuits"
	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/sessions"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he"
	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"
)

// evaluatorRuntime is a CircuitRuntime (for the service side) and EvaluationContext (for the circuit cide) implementation for the evaluatorRuntime role.
// This implementation:
//   - resolves all inputs by waiting for the runtime to set them,
//   - evaluates the homomorphic circuit and sets the future operands as it progresses,
//   - runs key operations as they are requested by the circuit, by passing the necessary signatures to the KeyOperationRunner
//     and retrieving their outputs from the ProtocolEngine.
//
// The evaluatorRuntime is a stateful object that is created and used for a single evaluation of a single circuit.
// It performs automatic translation of operand labels from the circuit definition to the running instance.
type evaluatorRuntime struct {

	// init
	ctx         context.Context // TODO: check if storing this context this way is a problem
	cd          circuits.Descriptor
	sess        *sessions.Session
	pkProvider  circuits.PublicKeyProvider
	fheProvider FHEProvider

	// protocols
	engine ProtocolEngine
	runner KeyOperationRunner

	// data
	inputs, ops, outputs map[circuits.OperandLabel]*circuits.FutureOperand
	opProvider           OperandProvider

	// eval
	eval he.Evaluator
}

// CircuitInstance (framework-facing) API

func (se *evaluatorRuntime) Init(ctx context.Context, md circuits.Metadata, nid sessions.NodeID) (err error) {

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

	se.eval, err = se.getEvaluatorForCircuit(se.sess.Params, md) // TODO pooled evaluators ?
	if err != nil {
		se.Logf("failed to get evaluator: %v", err)
	}
	return
}

func (se *evaluatorRuntime) getEvaluatorForCircuit(params sessions.FHEParameters, md circuits.Metadata) (eval he.Evaluator, err error) {

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
	return sessions.NewEvaluator(params, ks), nil

}

func (se *evaluatorRuntime) Eval(ctx context.Context, c circuits.Circuit) (err error) {
	return c(se)
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
	fop, has := se.inputs[opl]
	if !has {
		panic(fmt.Errorf("non registered input: %s", opl))
	}
	return fop
}

func (se *evaluatorRuntime) InputSum(opl circuits.OperandLabel, nids ...sessions.NodeID) *circuits.FutureOperand {

	nids, err := circuits.ApplyNodeMapping(se.cd.NodeMapping, nids...)
	if err != nil {
		panic(err)
	}

	opls, err := circuits.ExpandInputSumLabels(opl, se.sess, se.cd.CircuitID, nids...)
	if err != nil {
		panic(err)
	}

	opl = opl.ForCircuit(se.cd.CircuitID)
	fopOut := circuits.NewFutureOperand(opl)

	opOut := se.NewOperand(opl) // register the operand in the circuit
	opOut.Ciphertext = sessions.NewCiphertext(se.sess.Params, 1)

	rq := se.sess.Params.GetRLWEParameters().RingQ()

	var crs []byte
	crs = append(crs, se.sess.PublicSeed...)
	crs = append(crs, opl...)
	prng, err := sampling.NewKeyedPRNG(crs)
	if err != nil {
		panic(err)
	}
	sampler := ring.NewUniformSampler(prng, rq)
	sampler.Read(opOut.Ciphertext.Value[1])

	// TODO: parallel waiting/aggregating
	for _, opl := range opls {
		fop, exists := se.inputs[opl]
		if !exists {
			panic(fmt.Errorf("non registered input: %s", opl))
		}
		op := fop.Get()

		rq.Add(op.Ciphertext.Value[0], opOut.Ciphertext.Value[0], opOut.Ciphertext.Value[0])
	}

	fopOut.Set(*opOut)

	return fopOut

}

func (se *evaluatorRuntime) Load(opl circuits.OperandLabel) *circuits.Operand {
	if op, has := se.opProvider.GetOperand(opl); has {
		return op
	}
	panic("trying to load an unkown operand")
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

// keyOpExec requests the execution of the key operation sig, waits for its completion
// and sets the corresponding output operand.
func (se *evaluatorRuntime) keyOpExec(sig protocols.Signature, in circuits.Operand) (err error) {

	ctx := sessions.NewContext(se.ctx, se.sess.ID, se.cd.CircuitID)

	if err := se.runner.RunSignature(ctx, sig); err != nil {
		return fmt.Errorf("cannot run key operation %s: %w", sig, err)
	}

	pd, err := se.engine.AwaitCompleted(ctx, sig)
	if err != nil {
		return fmt.Errorf("error while waiting for key operation %s: %w", sig, err)
	}

	out, err := se.engine.GetOutput(ctx, pd)
	if err != nil {
		return fmt.Errorf("cannot get output of key operation %s: %w", sig, err)
	}

	outCt, isCt := out.Result.(*rlwe.Ciphertext)
	if !isCt {
		return fmt.Errorf("key operation %s output is not a ciphertext: %T", sig, out.Result)
	}

	outLabel := keyOpOutputLabel(in.OperandLabel, sig)
	outfop, isOutput := se.outputs[outLabel]
	if !isOutput {
		return fmt.Errorf("key op should have an output future operand for %s", outLabel)
	}
	outfop.Set(circuits.Operand{OperandLabel: outLabel, Ciphertext: outCt})
	return nil
}

func keyOpOutputLabel(inLabel circuits.OperandLabel, sig protocols.Signature) circuits.OperandLabel {
	return circuits.OperandLabel(fmt.Sprintf("%s-%s-out", inLabel, sig.Type))
}

func (se *evaluatorRuntime) getOperandLabelForRuntime(cOpLabel circuits.OperandLabel) circuits.OperandLabel {
	return cOpLabel.ForCircuit(se.cd.CircuitID).ForMapping(se.cd.NodeMapping)
}

func (se *evaluatorRuntime) DEC(in circuits.Operand, rec sessions.NodeID, params map[string]string) (err error) {
	var fop *circuits.FutureOperand
	var has bool
	if fop, has = se.ops[in.OperandLabel]; !has {
		fop = circuits.NewFutureOperand(in.OperandLabel)
		se.ops[in.OperandLabel] = fop
	}
	fop.Set(in)

	pparams := maps.Clone(params)
	pparams["target"] = string(se.cd.NodeMapping[string(rec)])
	pparams["op"] = string(in.OperandLabel)
	sig := se.keyOpSig(protocols.DEC, in, pparams)
	return se.keyOpExec(sig, in)
}

func (se *evaluatorRuntime) PCKS(in circuits.Operand, rec sessions.NodeID, params map[string]string) (err error) {
	if _, has := se.ops[in.OperandLabel]; !has {
		fop := circuits.NewFutureOperand(in.OperandLabel)
		fop.Set(in)
		se.ops[in.OperandLabel] = fop
	}
	sig := se.keyOpSig(protocols.PCKS, in, params)
	return se.keyOpExec(sig, in)
}

func (se *evaluatorRuntime) CircuitDescriptor() circuits.Descriptor {
	return se.cd.Clone()
}

func (se *evaluatorRuntime) Parameters() sessions.FHEParameters {
	return se.sess.Params
}

func (se *evaluatorRuntime) Logf(msg string, v ...any) {
	log.Printf("%s | [compute][%s] %s\n", se.cd.Evaluator, se.cd.CircuitID, fmt.Sprintf(msg, v...))
}
