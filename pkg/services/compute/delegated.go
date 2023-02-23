package compute

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/ldsec/helium/pkg/protocols"
	"github.com/ldsec/helium/pkg/transport"
	"github.com/ldsec/helium/pkg/utils"

	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/tuneinsight/lattigo/v4/bfv"
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

	id         pkg.CircuitID
	sess       *pkg.Session
	delegateID pkg.NodeID

	params bfv.Parameters

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
	de.f = cDef
	de.id = cid
	de.params, _ = bfv.NewParameters(*sess.Params, 65537)

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

	log.Printf("Node %s | started delegated context Execute of %s\n", de.sess.NodeID, de.id)

	// starts go routine to send the local inputs to delegate
	go func() {
		err := de.sendLocalInputs(ctx, de.outgoingOps)
		if err != nil {
			panic(err)
		}
	}()

	err := de.f(de)
	close(de.outputs)

	log.Printf("Node %s | delegate context Execute returned, err = %v \n", de.sess.NodeID, err)

	return err
}

func (de *delegatedEvaluatorContext) LocalInputs(lops []pkg.Operand) error {
	for _, op := range lops {
		de.outgoingOps <- op // TODO: filter
	}
	return nil
}

func (de *delegatedEvaluatorContext) IncomingInput(op pkg.Operand) error {
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
	ct, err := de.transport.GetCiphertext(pkg.NewContext(&de.sess.ID, &de.id), ctURL.CiphertextID())
	if err != nil {
		panic(err)
	}
	return pkg.Operand{OperandLabel: opl, Ciphertext: &ct.Ciphertext}
}

func (de *delegatedEvaluatorContext) Output(op pkg.Operand, to pkg.NodeID) {
	if to == de.sess.NodeID {
		op = de.Get(op.OperandLabel.ForCircuit(de.id))
		de.outputs <- op
	}
}

func (de *delegatedEvaluatorContext) runKeySwitch(pd protocols.Descriptor, id pkg.ProtocolID, in pkg.Operand) (out pkg.Operand, err error) {
	p, err := protocols.NewProtocol(pd, de.sess, id)
	if err != nil {
		return pkg.Operand{}, err
	}
	cks, _ := p.(protocols.KeySwitchInstance)

	op := de.Get(in.OperandLabel.ForCircuit(de.id))

	cks.Input(op.Ciphertext)

	cks.Aggregate(context.Background(), de.sess, &ProtocolEnvironment{outgoing: de.transport.OutgoingShares()})

	// agg, err := de.transport.GetAggregationFrom(pkg.NewContext(&de.sess.ID, &de.id), de.delegateID, pd.ID)
	// if agg.Error != nil {
	// 	return pkg.Operand{}, err
	// }

	// if pkg.NodeID(pd.Args["target"].(string)) == de.sess.NodeID {
	// 	out = pkg.Operand{Ciphertext: (<-cks.Output(*agg)).Result.(*rlwe.Ciphertext)}
	// }

	out.OperandLabel = pkg.OperandLabel(fmt.Sprintf("%s-%s-out", in.OperandLabel, id))
	return out, nil
}

func (de *delegatedEvaluatorContext) CKS(id pkg.ProtocolID, in pkg.Operand, params map[string]interface{}) (out pkg.Operand, err error) {
	parts := utils.NewSet(de.sess.Nodes)
	parts.Remove(pkg.NodeID(params["target"].(string)))
	pd := protocols.Descriptor{Type: protocols.DEC, Args: params, Aggregator: de.delegateID, Participants: parts.Elements()} // TODO receive desc from evaluator

	return de.runKeySwitch(pd, id, in)
}

func (de *delegatedEvaluatorContext) PCKS(id pkg.ProtocolID, in pkg.Operand, params map[string]interface{}) (out pkg.Operand, err error) {
	pd := protocols.Descriptor{Type: protocols.PCKS, Args: params, Aggregator: de.delegateID, Participants: de.sess.Nodes}
	return de.runKeySwitch(pd, id, in)
}

func (de *delegatedEvaluatorContext) SubCircuit(pkg.CircuitID, Circuit) (EvaluationContext, error) {
	panic("not implemented")
}

func (de *delegatedEvaluatorContext) Parameters() bfv.Parameters {
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
