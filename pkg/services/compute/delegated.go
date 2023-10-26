package compute

import (
	"context"
	"errors"
	"log"

	"github.com/ldsec/helium/pkg/protocols"
	"github.com/ldsec/helium/pkg/transport"

	"github.com/ldsec/helium/pkg/pkg"
	"github.com/tuneinsight/lattigo/v4/bgv"
)

// delegatedEvaluatorContext is an evaluation context for which circuit evaluation is
// delegated to a designated node (a delegated evaluator context assumes that the delegate
// computes the circuit correctly). The context "runs" the circuit with dummy operands
// and lattigo Evaluator methods, and simply perform the necessary interactive actions
// such as providing its inputs to the delagate, resolving protocol input-operands,
// sending its protocol shares and resolving its own outputs.
// The delegate is assumed to run a full evaluation context (see fullEvaluationContext).
type delegatedEvaluatorContext struct {
	dummyEvaluator

	transport transport.ComputeServiceTransport

	cid        pkg.CircuitID
	sess       *pkg.Session
	service    *Service
	delegateID pkg.NodeID

	params bgv.Parameters

	ops map[pkg.OperandLabel]*FutureOperand

	outgoingOps chan pkg.Operand
	outputs     chan pkg.Operand
	inputs      chan pkg.Operand

	f     Circuit
	cDesc CircuitDescription
}

func (s *Service) newDelegatedEvaluatorContext(delegateID pkg.NodeID, sess *pkg.Session, cid pkg.CircuitID, cDef Circuit) *delegatedEvaluatorContext {
	de := new(delegatedEvaluatorContext)
	de.delegateID = delegateID
	de.sess = sess
	de.service = s
	de.f = cDef
	de.cid = cid

	var err error
	de.params, err = bgv.NewParameters(*sess.Params, 65537)
	if err != nil {
		panic(err)
	}

	dummyCtx := newCircuitParserCtx(cid, de.params, nil)
	if err := cDef(dummyCtx); err != nil {
		panic(err)
	}
	de.cDesc = dummyCtx.cDesc

	de.outgoingOps = make(chan pkg.Operand, len(de.cDesc.InputSet)) // TODO too large of a buffer
	de.outputs = make(chan pkg.Operand, len(de.cDesc.OutputSet))    // TODO too large of a buffer
	de.inputs = make(chan pkg.Operand)
	de.transport = s.transport

	de.ops = make(map[pkg.OperandLabel]*FutureOperand)
	for opl := range de.cDesc.Ops {
		de.ops[opl] = &FutureOperand{}
	}

	return de
}

func (de *delegatedEvaluatorContext) Execute(ctx context.Context) error {

	log.Printf("Node %s | started delegated context Execute of %s\n", de.sess.NodeID, de.cid)

	// starts go routine to send the local inputs to delegate
	go func() {
		err := de.sendLocalInputs(ctx, de.outgoingOps)
		if err != nil {
			panic(err)
		}
	}()

	err := de.f(de)
	close(de.outputs)

	log.Printf("Node %s | %s | delegate context Execute returned, err = %v \n", de.sess.NodeID, de.cid, err)

	return err
}

func (de *delegatedEvaluatorContext) LocalInputs(lops []pkg.Operand) error {
	for _, op := range lops {
		de.outgoingOps <- op // TODO: filter
	}
	return nil
}

func (de *delegatedEvaluatorContext) IncomingOperand(op pkg.Operand) error {
	de.inputs <- op
	return nil
}

func (de *delegatedEvaluatorContext) LocalOutputs() chan pkg.Operand {
	return de.outputs
}

func (de *delegatedEvaluatorContext) Input(opl pkg.OperandLabel) pkg.Operand {
	return pkg.Operand{OperandLabel: opl}
}

func (de *delegatedEvaluatorContext) Set(op pkg.Operand) {

}

func (de *delegatedEvaluatorContext) Get(opl pkg.OperandLabel) pkg.Operand {
	ctURL, err := pkg.ParseURL(string(opl))
	if err != nil {
		panic(err)
	}
	if ctURL.Host == "" {
		ctURL.Host = string(de.delegateID)
	}
	ct, err := de.transport.GetCiphertext(pkg.NewContext(&de.sess.ID, &de.cid), ctURL.CiphertextID())
	if err != nil {
		panic(err)
	}
	return pkg.Operand{OperandLabel: opl, Ciphertext: &ct.Ciphertext}
}

func (de *delegatedEvaluatorContext) Output(op pkg.Operand, to pkg.NodeID) {
	if to == de.sess.NodeID {
		op = de.Get(op.OperandLabel)
		de.outputs <- op
	}
}

func (de *delegatedEvaluatorContext) runKeySwitch(sig protocols.Signature, in pkg.Operand) (out pkg.Operand, err error) {
	op := de.Get(in.OperandLabel.ForCircuit(de.cid))
	ctx := pkg.NewContext(&de.sess.ID, &de.cid)
	return de.service.GetProtoDescAndRunKeySwitch(ctx, sig, op)
}

func (de *delegatedEvaluatorContext) DEC(in pkg.Operand, params map[string]string) (out pkg.Operand, err error) {
	sig := GetProtocolSignature(protocols.DEC, in.OperandLabel.ForCircuit(de.cid), params)
	return de.runKeySwitch(sig, in)
}

func (de *delegatedEvaluatorContext) PCKS(in pkg.Operand, params map[string]string) (out pkg.Operand, err error) {
	sig := GetProtocolSignature(protocols.PCKS, in.OperandLabel.ForCircuit(de.cid), params)
	return de.runKeySwitch(sig, in)
}

func (de *delegatedEvaluatorContext) SubCircuit(pkg.CircuitID, Circuit) (EvaluationContext, error) {
	panic("not implemented")
}

func (de *delegatedEvaluatorContext) Parameters() bgv.Parameters {
	return de.params
}

func (de *delegatedEvaluatorContext) CircuitDescription() CircuitDescription {
	return de.cDesc
}

func (de *delegatedEvaluatorContext) sendLocalInputs(ctx context.Context, outOps chan pkg.Operand) error {
	errs := make([]error, 0)
	for op := range outOps {
		log.Printf("%s | sending input to %s: %s\n", de.sess.NodeID, de.delegateID, op.OperandLabel)
		ct := pkg.Ciphertext{Ciphertext: *op.Ciphertext, CiphertextMetadata: pkg.CiphertextMetadata{ID: pkg.CiphertextID(op.OperandLabel)}}
		errs = append(errs, de.transport.PutCiphertext(ctx, de.delegateID, ct))
	}
	return errors.Join(errs...)
}
