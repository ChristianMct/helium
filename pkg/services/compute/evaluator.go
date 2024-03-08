package compute

import (
	"context"
	"fmt"
	"log"

	"golang.org/x/exp/maps"

	"github.com/ldsec/helium/pkg/circuits"
	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/protocols"
	"github.com/tuneinsight/lattigo/v4/bgv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe/ringqp"
)

type ProtocolExecutor interface {
	RunKeyOperation(ctx context.Context, sig protocols.Signature) error
}

type fheEvaluator struct {
	*bgv.Evaluator
}

type evaluator struct {

	// init
	ctx   context.Context // TODO: check if storing this context this way is a problem
	cDesc circuits.Descriptor
	//c      circuits.Circuit
	//params bgv.Parameters
	sess        *pkg.Session
	fheProvider FHEProvider

	// protocols
	protoExec ProtocolExecutor
	*protocols.CompleteMap

	// data

	inputs, ops, outputs map[circuits.OperandLabel]*circuits.FutureOperand
	ctbk                 OperandBackend

	// eval
	*fheEvaluator
}

// CircuitInstance (framework-facing) API

func (se *evaluator) Init(ctx context.Context, ci circuits.Info) (err error) {

	se.ops = make(map[circuits.OperandLabel]*circuits.FutureOperand)
	se.inputs = make(map[circuits.OperandLabel]*circuits.FutureOperand)
	for inLabel := range ci.InputSet {
		fop := circuits.NewFutureOperand(inLabel)
		se.inputs[inLabel] = fop
		se.ops[inLabel] = fop
	}

	se.outputs = make(map[circuits.OperandLabel]*circuits.FutureOperand)
	for outLabel := range ci.OutputSet {
		fop := circuits.NewFutureOperand(outLabel)
		se.outputs[outLabel] = fop
		se.ops[outLabel] = fop
	}

	se.CompleteMap = protocols.NewCompletedProt(maps.Values(ci.KeySwitchOps))

	se.fheEvaluator, err = se.fheProvider.GetEvaluator(ctx, ci.NeedRlk, ci.GaloisKeys.Elements())
	if err != nil {
		return err
	}
	return
}

func (se *evaluator) Eval(ctx context.Context, c circuits.Circuit) (err error) {
	err = c(se)
	if err != nil {
		return err
	}
	return se.Wait()

}

func (se *evaluator) IncomingOperand(op circuits.Operand) error {
	fop, has := se.inputs[op.OperandLabel]
	if !has {
		return fmt.Errorf("unexpected input operand: %s", op.OperandLabel)
	}
	fop.Set(op)
	return nil
}

func (se *evaluator) GetOperand(_ context.Context, opl circuits.OperandLabel) (op *circuits.Operand, has bool) {
	fop, has := se.ops[opl]
	if !has {
		return
	}
	opg := fop.Get()
	return &opg, true
}

func (se *evaluator) GetFutureOperand(_ context.Context, opl circuits.OperandLabel) (op *circuits.FutureOperand, has bool) {
	fop, has := se.ops[opl]
	return fop, has
}

// EvaluationContext (user-facing) API

func (se *evaluator) Input(opl circuits.OperandLabel) *circuits.FutureOperand {
	opl = opl.ForCircuit(se.cDesc.ID).ForMapping(se.cDesc.NodeMapping)
	op, has := se.inputs[opl]
	if !has {
		panic(fmt.Errorf("non registered input: %s", opl))
	}
	return op
}

func (se *evaluator) Load(opl circuits.OperandLabel) *circuits.Operand {
	opl = opl.ForCircuit(se.cDesc.ID).ForMapping(se.cDesc.NodeMapping)
	op, err := se.ctbk.Get(opl)
	if err != nil {
		panic(err)
	}
	return op
}

func (se *evaluator) NewOperand(opl circuits.OperandLabel) circuits.Operand {
	opl = opl.ForCircuit(se.cDesc.ID).ForMapping(se.cDesc.NodeMapping)
	return circuits.Operand{OperandLabel: opl}
}

func (se *evaluator) Set(op circuits.Operand) {
	panic("not supported yet")
}

func (se *evaluator) keyOpSig(pt protocols.Type, in circuits.Operand, params map[string]string) protocols.Signature {
	params["op"] = string(in.OperandLabel)
	return protocols.Signature{Type: pt, Args: params}
}

func (se *evaluator) keyOpExec(sig protocols.Signature, in circuits.Operand) (err error) {

	// var isOutput bool

	ctx := pkg.NewContext(&se.sess.ID, (*pkg.CircuitID)(&se.cDesc.ID))

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

func (se *evaluator) getOperandLabel(cOpLabel circuits.OperandLabel) circuits.OperandLabel {
	return cOpLabel.ForCircuit(se.cDesc.ID).ForMapping(se.cDesc.NodeMapping)
}

func (se *evaluator) DEC(in circuits.Operand, rec pkg.NodeID, params map[string]string) (err error) {
	//in.OperandLabel = se.getOperandLabel(in.OperandLabel)
	if _, has := se.ops[in.OperandLabel]; !has {
		fop := circuits.NewFutureOperand(in.OperandLabel)
		fop.Set(in)
		se.ops[in.OperandLabel] = fop
	}
	pparams := maps.Clone(params)
	pparams["target"] = string(se.cDesc.NodeMapping[string(rec)])
	pparams["op"] = string(in.OperandLabel)
	sig := se.keyOpSig(protocols.DEC, in, pparams)
	return se.keyOpExec(sig, in)
}

func (se *evaluator) PCKS(in circuits.Operand, rec pkg.NodeID, params map[string]string) (err error) {
	//in.OperandLabel = se.getOperandLabel(in.OperandLabel)
	if _, has := se.ops[in.OperandLabel]; !has {
		fop := circuits.NewFutureOperand(in.OperandLabel)
		fop.Set(in)
		se.ops[in.OperandLabel] = fop
	}
	sig := se.keyOpSig(protocols.PCKS, in, params)
	return se.keyOpExec(sig, in)
}

func (se *evaluator) Output(op circuits.Operand, nid pkg.NodeID) {
	//opl := op.OperandLabel.ForCircuit(se.cDesc.ID).ForMapping(se.cDesc.InputParties)
	se.outputs[op.OperandLabel].Set(op)
}

func (se *evaluator) Parameters() bgv.Parameters {
	return se.sess.Params
}

func (se *evaluator) NewEvaluator() circuits.Evaluator {
	return &fheEvaluator{se.fheEvaluator.ShallowCopy()}
}

func (se *evaluator) Logf(msg string, v ...any) {
	log.Printf("%s | [%s] %s\n", se.cDesc.Evaluator, se.cDesc.ID, fmt.Sprintf(msg, v...))
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

func newLattigoEvaluator(ctx context.Context, relin bool, galEls []uint64, params bgv.Parameters, pkbk PublicKeyBackend) (eval *fheEvaluator, err error) {
	rlk := new(rlwe.RelinearizationKey)
	if relin {
		rlk, err = pkbk.GetRelinearizationKey(ctx)
		if err != nil {
			return nil, err
		}
	}

	gks := make([]*rlwe.GaloisKey, 0, len(galEls))
	for _, galEl := range galEls {
		var err error
		gk, err := pkbk.GetGaloisKey(ctx, galEl)
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
