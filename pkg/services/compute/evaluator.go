package compute

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/protocols"
	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v3/bfv"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ServiceEvaluationContext defines the interface that is available to the service
// to access evaluation contexts of a particular circuit evaluation.
type ServiceEvaluationContext interface {

	// CircuitDescription returns the CircuitDescription for the circuit executing within this context.
	CircuitDescription() CircuitDescription

	// LocalInput provides the local inputs to the circuit executing within this context.
	LocalInputs([]pkg.Operand) error

	// LocalOutput returns a channel where the circuit executing within this context will write its outputs.
	LocalOutputs() chan pkg.Operand

	// Execute executes the circuit of the context.
	Execute(context.Context) error

	// Get returns the executing circuit operand with the given label.
	Get(pkg.OperandLabel) pkg.Operand
}

// delegatedEvaluatorContext is an evaluation context for which circuit evaluation is
// delegated to a designated node (a delegated evaluator context assumes that the delegate
// computes the circuit correctly). The context "runs" the circuit with dummy operands
// and lattigo Evaluator methods, and simply perform the necessary interactive actions
// such as providing its inputs to the delagate, resolving protocol input-operands,
// sending its protocol shares and resolving its own outputs.
// The delegate is assumed to run a full evaluation context (see fullEvaluationContext).
type delegatedEvaluatorContext struct {
	dummyEvaluator
	id         pkg.CircuitID
	sess       *pkg.Session
	delegateId pkg.NodeID
	delegate   api.ComputeServiceClient

	params bfv.Parameters

	outgoingOps chan pkg.Operand
	outputs     chan pkg.Operand

	f     Circuit
	cDesc CircuitDescription
}

func newDelegatedEvaluatorContext(delegateId pkg.NodeID, delegate api.ComputeServiceClient, sess *pkg.Session, cid pkg.CircuitID, cDef Circuit) *delegatedEvaluatorContext {
	de := new(delegatedEvaluatorContext)
	de.delegateId = delegateId
	de.delegate = delegate
	de.sess = sess
	de.f = cDef
	de.id = cid
	de.params, _ = bfv.NewParameters(*sess.Params, 65537)

	dummyCtx := newCircuitParserCtx(cid, de.params, nil)
	cDef(dummyCtx)
	de.cDesc = dummyCtx.cDesc

	de.outgoingOps = make(chan pkg.Operand, len(de.cDesc.InputSet)) // TODO too large of a buffer
	de.outputs = make(chan pkg.Operand, len(de.cDesc.OutputSet))    // TODO too large of a buffer

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

	return pkg.Operand{OperandLabel: opl, Ciphertext: &bfv.Ciphertext{Ciphertext: &ct.Ciphertext}}
}

func (de *delegatedEvaluatorContext) Output(op pkg.Operand) {
	outUrl := NewURL(string(op.OperandLabel))
	if len(outUrl.Host) == 0 || outUrl.Host == string(de.sess.NodeID) {
		op = de.Get(op.OperandLabel.ForCircuit(de.id))
		de.outputs <- op
	}
}

func (de *delegatedEvaluatorContext) CKS(id pkg.ProtocolID, in pkg.Operand, params map[string]interface{}) (out pkg.Operand, err error) {

	_, hasTarget := params["target"]
	if !hasTarget {
		return pkg.Operand{}, fmt.Errorf("CKS parameter should have a target")
	}
	op := de.Get(in.OperandLabel.ForCircuit(de.id))

	cks := protocols.NewCKSProtocol(de.sess, pkg.NodeID(params["target"].(string)), params["lvl"].(int), params["smudging"].(float64))
	var aggregator pkg.NodeID
	if agg, hasAgg := params["aggregator"]; hasAgg {
		aggregator = pkg.NodeID(agg.(string))
		if aggregator != de.delegateId {
			panic("not supported yet") // TODO
		}
	} else {
		aggregator = de.delegateId
	}

	cks.Init(protocols.Descriptor{Type: api.ProtocolType_CKS, Aggregator: aggregator, Participants: de.sess.Nodes}, de.sess) // TODO: delayed init (and T-out-of-N))
	cks.Inputs() <- op

	part := utils.NewSet(cks.Desc().Participants)
	if part.Contains(de.sess.NodeID) && cks.Target() != de.sess.NodeID {
		log.Printf("Node %s | will provide its share to %s\n", de.sess.NodeID, cks.Desc())

		share, err := cks.GetShare(protocols.ShareRequest{AggregateFor: []pkg.NodeID{de.sess.NodeID}})
		if err != nil {
			return pkg.Operand{}, err
		}
		shareb, err := share.Share().MarshalBinary()
		if err != nil {
			return pkg.Operand{}, err
		}

		outctx := pkg.NewOutgoingContext(&de.sess.NodeID, &de.sess.ID, &de.id)
		one := uint64(1)
		_, err = de.delegate.PutShare(outctx, &api.Share{ProtocolID: &api.ProtocolID{ProtocolID: string(id)}, Round: &one, Share: shareb})
		if err != nil {
			panic(err)
		}
	}

	if cks.Aggregator == de.sess.NodeID {
		out = <-cks.Outputs()
	}
	out.OperandLabel = pkg.OperandLabel(fmt.Sprintf("//%s/%s-out-0", cks.Target(), id))
	return out, nil
}

func (de *delegatedEvaluatorContext) PCKS(id pkg.ProtocolID, in pkg.Operand, params map[string]interface{}) (out pkg.Operand, err error) {

	_, hasTarget := params["target"]
	if !hasTarget {
		return pkg.Operand{}, fmt.Errorf("PCKS parameter should have a target")
	}
	op := de.Get(in.OperandLabel.ForCircuit(de.id))

	pcks := protocols.NewPCKSProtocol(de.sess, pkg.NodeID(params["target"].(string)), params["lvl"].(int), params["smudging"].(float64))
	var aggregator pkg.NodeID
	if agg, hasAgg := params["aggregator"]; hasAgg {
		aggregator = pkg.NodeID(agg.(string))
		if aggregator != de.delegateId {
			panic("not supported yet") // TODO
		}
	} else {
		aggregator = de.delegateId
	}

	pcks.Init(protocols.Descriptor{Type: api.ProtocolType_PCKS, Aggregator: aggregator, Participants: de.sess.Nodes}, de.sess) // TODO: delayed init (and T-out-of-N))
	pcks.Inputs() <- op

	part := utils.NewSet(pcks.Desc().Participants)
	if part.Contains(de.sess.NodeID) {
		log.Printf("Node %s | will provide its share to %s\n", de.sess.NodeID, pcks.Desc())

		share, err := pcks.GetShare(protocols.ShareRequest{AggregateFor: []pkg.NodeID{de.sess.NodeID}})
		if err != nil {
			return pkg.Operand{}, err
		}
		shareb, err := share.Share().MarshalBinary()
		if err != nil {
			return pkg.Operand{}, err
		}

		if pcks.Aggregator != de.sess.NodeID {
			outctx := pkg.NewOutgoingContext(&de.sess.NodeID, &de.sess.ID, &de.id)
			one := uint64(1)
			_, err = de.delegate.PutShare(outctx, &api.Share{ProtocolID: &api.ProtocolID{ProtocolID: string(id)}, Round: &one, Share: shareb})
			if err != nil {
				panic(err)
			}
		} else {
			pcks.PutShare(share)
		}
	}

	if pcks.Aggregator == de.sess.NodeID {
		out = <-pcks.Outputs()
	}
	out.OperandLabel = pkg.OperandLabel(fmt.Sprintf("//%s/%s-out-0", pcks.Target(), id))
	return out, nil
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
		log.Printf("Node %s | sending input to %s: %s\n", de.sess.NodeID, de.delegateId, op.OperandLabel)
		ct := pkg.Ciphertext{Ciphertext: *op.Ciphertext.Ciphertext, CiphertextMetadata: pkg.CiphertextMetadata{ID: pkg.CiphertextID(op.OperandLabel)}}

		outCtx := pkg.GetOutgoingContext(ctx, de.sess.NodeID)

		_, err := de.delegate.PutCiphertext(outCtx, ct.ToGRPC())
		if err != nil {
			log.Printf("Node %s | error while sending input to %s: %s\n", de.sess.ID, de.delegateId, err)
		}

	}
	return nil
}

// fullEvaluatorContext is an evaluation context that performs the full circuit evaluation.
// It resolve the remote inputs from the full nodes and waits for inputs from the light nodes.
// It evaluates the homomorphic operations and compute the outputs of the circuit.
type fullEvaluatorContext struct {
	bfv.Evaluator

	id pkg.CircuitID

	sess *pkg.Session

	peers map[pkg.NodeID]api.ComputeServiceClient

	params bfv.Parameters

	outgoingOps, ops, inputOps map[pkg.OperandLabel]*FutureOperand

	protos map[pkg.ProtocolID]protocols.Interface

	inputs, outputs chan pkg.Operand

	f     Circuit
	cDesc CircuitDescription
}

func newFullEvaluationContext(sess *pkg.Session, peers map[pkg.NodeID]api.ComputeServiceClient, id pkg.CircuitID, cDef Circuit, nodeMapping map[string]pkg.NodeID) *fullEvaluatorContext {
	se := new(fullEvaluatorContext)
	se.id = id
	se.sess = sess
	se.peers = peers

	se.params, _ = bfv.NewParameters(*sess.Params, 65537)
	eval := bfv.NewEvaluator(se.params, rlwe.EvaluationKey{Rlk: sess.Rlk})
	se.Evaluator = eval

	dummyCtx := newCircuitParserCtx(id, se.params, nodeMapping)
	cDef(dummyCtx)
	se.cDesc = dummyCtx.cDesc

	se.inputOps = make(map[pkg.OperandLabel]*FutureOperand)
	se.ops = make(map[pkg.OperandLabel]*FutureOperand)
	se.outgoingOps = make(map[pkg.OperandLabel]*FutureOperand)

	// adds all own-inputs to the outgoing ops
	for inLabel := range se.cDesc.InputSet {
		in := NewURL(string(inLabel))
		op := &FutureOperand{}
		if len(in.Host) != 0 && in.Host == string(sess.ID) {
			se.outgoingOps[inLabel] = op
		}
		se.inputOps[inLabel] = op
		se.ops[inLabel] = op
	}

	for opl := range se.cDesc.Ops {
		se.ops[opl] = &FutureOperand{}
	}

	se.protos = make(map[pkg.ProtocolID]protocols.Interface)
	for protoId, cksParams := range se.cDesc.CKSs {
		se.protos[protoId] = protocols.NewCKSProtocol(sess, pkg.NodeID(cksParams["target"].(string)), cksParams["lvl"].(int), cksParams["smudging"].(float64))
		var aggregator pkg.NodeID
		if agg, hasAgg := cksParams["aggregator"]; hasAgg {
			aggregator = pkg.NodeID(agg.(string))
		} else {
			aggregator = pkg.NodeID(cksParams["target"].(string)) // TODO: check that aggregator is full node
		}
		se.protos[protoId].Init(protocols.Descriptor{Type: api.ProtocolType_CKS, Aggregator: aggregator, Participants: sess.Nodes}, sess) // TODO: delayed init (and T-out-of-N))
	}

	for protoId, cksParams := range se.cDesc.PCKSs {
		se.protos[protoId] = protocols.NewPCKSProtocol(sess, pkg.NodeID(cksParams["target"].(string)), cksParams["lvl"].(int), cksParams["smudging"].(float64))
		var aggregator pkg.NodeID
		if agg, hasAgg := cksParams["aggregator"]; hasAgg {
			aggregator = pkg.NodeID(agg.(string))
		} else {
			aggregator = pkg.NodeID(cksParams["target"].(string)) // TODO: check that aggregator is full node
		}
		se.protos[protoId].Init(protocols.Descriptor{Type: api.ProtocolType_PCKS, Aggregator: aggregator, Participants: sess.Nodes}, sess) // TODO: delayed init (and T-out-of-N))
	}

	se.inputs, se.outputs = make(chan pkg.Operand, len(se.cDesc.InputSet)), make(chan pkg.Operand, len(se.cDesc.OutputSet))

	se.f = cDef

	return se
}

func (se *fullEvaluatorContext) Execute(ctx context.Context) error {

	log.Printf("Node %s | started full context Execute of %s\n", se.sess.NodeID, se.id)

	se.resolveRemoteInputs(ctx, se.cDesc.InputSet)

	err := se.f(se)

	close(se.outputs)
	log.Printf("Node %s | full context Execute returned, err = %v \n", se.sess.NodeID, err)

	return err
}

func (se *fullEvaluatorContext) LocalInputs(lops []pkg.Operand) error {
	for _, lop := range lops {
		se.inputs <- lop // TODO validate
	}
	return nil
}

func (se *fullEvaluatorContext) LocalOutputs() chan pkg.Operand {
	return se.outputs
}

func (se *fullEvaluatorContext) Input(opl pkg.OperandLabel) pkg.Operand {
	fop, exists := se.inputOps[opl.ForCircuit(se.id)]
	if !exists {
		panic(fmt.Errorf("unexpected input: %s", opl))
	}
	op := <-fop.Await()
	log.Printf("Node %s | got input %s\n", se.sess.NodeID, op.OperandLabel)
	return op
}

func (se *fullEvaluatorContext) Set(op pkg.Operand) {
	se.ops[op.OperandLabel.ForCircuit(se.id)].Done(op)
}

func (se *fullEvaluatorContext) Get(opl pkg.OperandLabel) pkg.Operand {
	if fop, exists := se.ops[opl]; exists {
		return <-fop.Await()
	}
	panic(fmt.Errorf("Get on unknown op %s, %v", opl, se.ops))
}

func (se *fullEvaluatorContext) Output(op pkg.Operand) {
	se.ops[op.OperandLabel.ForCircuit(se.id)].Done(op)
	se.outputs <- pkg.Operand{OperandLabel: op.OperandLabel.ForCircuit(se.id), Ciphertext: op.Ciphertext}
}

func (se *fullEvaluatorContext) SubCircuit(_ pkg.CircuitID, _ Circuit) (EvaluationContext, error) {
	panic("not implemented") // TODO: Implement
}

func (se *fullEvaluatorContext) CKS(id pkg.ProtocolID, in pkg.Operand, params map[string]interface{}) (out pkg.Operand, err error) {
	se.Set(in)

	_, hasTarget := params["target"]
	if !hasTarget {
		return pkg.Operand{}, fmt.Errorf("CKS parameter should have a target")
	}
	cksInt := se.protos[id]

	cks, isCKS := cksInt.(*protocols.CKSProtocol)
	if !isCKS {
		return pkg.Operand{}, fmt.Errorf("bad protocol type")
	}

	cks.Inputs() <- in

	part := utils.NewSet(cks.Desc().Participants)
	if part.Contains(se.sess.NodeID) && cks.Target() != se.sess.NodeID {
		log.Printf("Node %s | will provide its share to %s\n", se.sess.NodeID, cks.Desc())
		aggregator, hasCli := se.peers[cks.Desc().Aggregator]
		if !hasCli {
			return pkg.Operand{}, fmt.Errorf("no client for aggregator \"%s\"", cks.Desc().Aggregator)
		}

		share, err := cks.GetShare(protocols.ShareRequest{AggregateFor: []pkg.NodeID{se.sess.NodeID}})
		if err != nil {
			return pkg.Operand{}, err
		}
		shareb, err := share.Share().MarshalBinary()
		if err != nil {
			return pkg.Operand{}, err
		}

		outctx := pkg.NewOutgoingContext(&se.sess.NodeID, &se.sess.ID, &se.id)
		one := uint64(1)
		_, err = aggregator.PutShare(outctx, &api.Share{ProtocolID: &api.ProtocolID{ProtocolID: string(id)}, Round: &one, Share: shareb})
		if err != nil {
			panic(err)
		}
	}

	if cks.Aggregator == se.sess.NodeID {
		out = <-cks.Outputs()
	}
	out.OperandLabel = pkg.OperandLabel(fmt.Sprintf("//%s/%s-out-0", cks.Target(), id))
	return out, nil
}

func (se *fullEvaluatorContext) PCKS(id pkg.ProtocolID, in pkg.Operand, params map[string]interface{}) (out pkg.Operand, err error) {
	se.Set(in)

	_, hasTarget := params["target"]
	if !hasTarget {
		return pkg.Operand{}, fmt.Errorf("PCKS parameter should have a target")
	}
	pcksInt := se.protos[id]

	pcks, isPCKS := pcksInt.(*protocols.PCKSProtocol)
	if !isPCKS {
		return pkg.Operand{}, fmt.Errorf("bad protocol type")
	}

	pcks.Inputs() <- in

	part := utils.NewSet(pcks.Desc().Participants)
	if part.Contains(se.sess.NodeID) {
		log.Printf("Node %s | will provide its share to %s\n", se.sess.NodeID, pcks.Desc())

		share, err := pcks.GetShare(protocols.ShareRequest{AggregateFor: []pkg.NodeID{se.sess.NodeID}})
		if err != nil {
			return pkg.Operand{}, err
		}
		shareb, err := share.Share().MarshalBinary()
		if err != nil {
			return pkg.Operand{}, err
		}

		if pcks.Aggregator != se.sess.NodeID {
			aggregator, hasCli := se.peers[pcks.Desc().Aggregator]
			if !hasCli {
				return pkg.Operand{}, fmt.Errorf("no client for aggregator \"%s\"", pcks.Desc().Aggregator)
			}

			outctx := pkg.NewOutgoingContext(&se.sess.NodeID, &se.sess.ID, &se.id)
			one := uint64(1)
			_, err = aggregator.PutShare(outctx, &api.Share{ProtocolID: &api.ProtocolID{ProtocolID: string(id)}, Round: &one, Share: shareb})
			if err != nil {
				panic(err)
			}
		} else {
			log.Printf("Node %s | computed its own share in %s\n", se.sess.NodeID, pcks.Desc())
			pcks.PutShare(share)
		}
	}

	if pcks.Aggregator == se.sess.NodeID {
		out = <-pcks.Outputs()
	}
	out.OperandLabel = pkg.OperandLabel(fmt.Sprintf("//%s/%s-out-0", pcks.Target(), id))
	return out, nil
}

func (se *fullEvaluatorContext) Parameters() bfv.Parameters {
	return se.params
}

func (se *fullEvaluatorContext) CircuitDescription() CircuitDescription {
	return se.cDesc
}

func (se *fullEvaluatorContext) resolveRemoteInputs(ctx context.Context, ins utils.Set[pkg.OperandLabel]) {

	// TODO parallel querying

	// fetches all inputs from full nodes
	go func() {
		for in := range ins {

			var op pkg.Operand

			inUrl := NewURL(string(in))
			if len(inUrl.Host) == 0 || inUrl.Host == string(se.sess.NodeID) {
				log.Printf("Node %s | skipping input %s\n", se.sess.NodeID, in)
				continue
			}

			peer, hasCli := se.peers[inUrl.NodeID()]
			if !hasCli {
				continue // TODO should be a better way to check if peer is a light node
			}

			outctx := pkg.GetOutgoingContext(ctx, se.sess.NodeID)
			resp, err := peer.GetCiphertext(outctx, &api.CiphertextRequest{Id: inUrl.CiphertextID().ToGRPC()})
			if err != nil {
				panic(err)
			}

			var ct *pkg.Ciphertext
			ct, err = pkg.NewCiphertextFromGRPC(resp)
			if err != nil {
				panic(status.Errorf(codes.InvalidArgument, "invalid ciphertext: %s", err))
			}
			op = pkg.Operand{OperandLabel: in, Ciphertext: &bfv.Ciphertext{Ciphertext: &ct.Ciphertext}}
			se.inputs <- op
		}
	}()

	go func() {
		for op := range se.inputs {
			if fop, exists := se.inputOps[op.OperandLabel]; exists {
				fop.Done(op)
			} else {
				panic(fmt.Errorf("unexpected input %s", op.OperandLabel))
			}
			// if fop, exists := se.outgoingOps[op.OperandLabel]; exists {
			// 	fop.Done(op)
			// }
		}
	}()

	return
}

type FutureOperand struct {
	m        sync.Mutex
	op       *pkg.Operand
	awaiters []chan pkg.Operand
}

func (fop *FutureOperand) Await() <-chan pkg.Operand {
	c := make(chan pkg.Operand, 1)
	fop.m.Lock()
	defer fop.m.Unlock()

	if fop.op != nil {
		c <- *fop.op
	} else {
		fop.awaiters = append(fop.awaiters, c)
	}
	return c
}

func (fop *FutureOperand) Done(op pkg.Operand) {
	fop.m.Lock()
	defer fop.m.Unlock()
	if fop.op != nil {
		panic("Done called multiple times")
	}
	fop.op = &op
	for _, aw := range fop.awaiters {
		aw <- op // TODO copy ?
		close(aw)
	}
}
