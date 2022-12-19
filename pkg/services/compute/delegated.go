package compute

import (
	"context"
	"fmt"
	"log"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/protocols"
	"github.com/ldsec/helium/pkg/services"
	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	*services.Environment

	id         pkg.CircuitID
	sess       *pkg.Session
	delegateID pkg.NodeID
	delegate   api.ComputeServiceClient

	params bfv.Parameters

	outgoingOps chan pkg.Operand
	outputs     chan pkg.Operand

	f     Circuit
	cDesc CircuitDescription
}

func (s *Service) newDelegatedEvaluatorContext(delegateID pkg.NodeID, delegate api.ComputeServiceClient, sess *pkg.Session, cid pkg.CircuitID, cDef Circuit) *delegatedEvaluatorContext {
	de := new(delegatedEvaluatorContext)
	de.delegateID = delegateID
	de.delegate = delegate
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

	de.Environment = s.Environment

	de.Environment.Connect(map[pkg.NodeID]services.ProtocolClient{delegateID: delegate})

	return de
}

func (de *delegatedEvaluatorContext) Execute(ctx context.Context) error {

	log.Printf("Node %s | started delegated context Execute of %s\n", de.sess.NodeID, de.id)

	de.Environment.Run(ctx)

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

func (de *delegatedEvaluatorContext) LocalOutputs() chan pkg.Operand {
	return de.outputs
}

func (de *delegatedEvaluatorContext) Input(opl pkg.OperandLabel) pkg.Operand {
	return pkg.Operand{OperandLabel: opl}
}

func (de *delegatedEvaluatorContext) Set(op pkg.Operand) {

}

func (de *delegatedEvaluatorContext) Get(opl pkg.OperandLabel) pkg.Operand {

	log.Printf("Node %s | fetching %s\n", de.sess.NodeID, opl)

	outctx := pkg.NewOutgoingContext(&de.sess.NodeID, &de.sess.ID, &de.id)
	resp, err := de.delegate.GetCiphertext(outctx, &api.CiphertextRequest{Id: pkg.CiphertextID(opl).ToGRPC()})
	if err != nil {
		panic(err)
	}

	var ct *pkg.Ciphertext
	ct, err = pkg.NewCiphertextFromGRPC(resp)
	if err != nil {
		panic(status.Errorf(codes.InvalidArgument, "invalid ciphertext: %s", err))
	}

	return pkg.Operand{OperandLabel: opl, Ciphertext: &ct.Ciphertext}
}

func (de *delegatedEvaluatorContext) Output(op pkg.Operand) {
	outURL := NewURL(string(op.OperandLabel))
	if len(outURL.Host) == 0 || outURL.Host == string(de.sess.NodeID) {
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
	cks.Run(context.Background(), de.sess, de.EnvironmentForProtocol(id))

	if pkg.NodeID(pd.Args["target"].(string)) == de.sess.NodeID {
		out = pkg.Operand{Ciphertext: <-cks.Output()}
	}

	out.OperandLabel = pkg.OperandLabel(fmt.Sprintf("//%s/%s-out-0", pd.Args["target"], id))
	return out, nil
}

func (de *delegatedEvaluatorContext) CKS(id pkg.ProtocolID, in pkg.Operand, params map[string]interface{}) (out pkg.Operand, err error) {
	pd := protocols.Descriptor{Type: protocols.DEC, Args: params, Aggregator: de.delegateID, Participants: de.sess.Nodes}
	return de.runKeySwitch(pd, id, in)
}

func (de *delegatedEvaluatorContext) PCKS(id pkg.ProtocolID, in pkg.Operand, params map[string]interface{}) (out pkg.Operand, err error) {
	pd := protocols.Descriptor{Type: protocols.PCKS, Args: params, Aggregator: de.delegateID, Participants: de.sess.Nodes, Receivers: []pkg.NodeID{de.delegateID}}
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
	for op := range outOps {
		log.Printf("Node %s | sending input to %s: %s\n", de.sess.NodeID, de.delegateID, op.OperandLabel)
		ct := pkg.Ciphertext{Ciphertext: *op.Ciphertext, CiphertextMetadata: pkg.CiphertextMetadata{ID: pkg.CiphertextID(op.OperandLabel)}}

		outCtx := pkg.GetOutgoingContext(ctx, de.sess.NodeID)

		_, err := de.delegate.PutCiphertext(outCtx, ct.ToGRPC())
		if err != nil {
			log.Printf("Node %s | error while sending input to %s: %s\n", de.sess.ID, de.delegateID, err)
			return err
		}

	}
	return nil
}
