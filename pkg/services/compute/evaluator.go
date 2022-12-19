package compute

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/protocols"
	"github.com/ldsec/helium/pkg/services"
	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ServiceEvaluationEnvironment defines the interface that is available to the service
// to access evaluation contexts of a particular circuit evaluation.
type ServiceEvaluationEnvironment interface {

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

// fullEvaluatorContext is an evaluation context that performs the full circuit evaluation.
// It resolve the remote inputs from the full nodes and waits for inputs from the light nodes.
// It evaluates the homomorphic operations and compute the outputs of the circuit.
type fullEvaluatorContext struct {
	bfv.Evaluator
	*services.Environment

	peers map[pkg.NodeID]api.ComputeServiceClient

	sess   *pkg.Session
	params bfv.Parameters
	id     pkg.CircuitID

	outgoingOps, ops, inputOps map[pkg.OperandLabel]*FutureOperand

	protos map[pkg.ProtocolID]protocols.KeySwitchInstance

	inputs, outputs chan pkg.Operand

	f     Circuit
	cDesc CircuitDescription
}

func (s *Service) newFullEvaluationContext(sess *pkg.Session, peers map[pkg.NodeID]api.ComputeServiceClient, id pkg.CircuitID, cDef Circuit, nodeMapping map[string]pkg.NodeID) *fullEvaluatorContext {
	se := new(fullEvaluatorContext)
	se.id = id
	se.sess = sess
	se.peers = peers

	se.params, _ = bfv.NewParameters(*sess.Params, 65537)
	eval := bfv.NewEvaluator(se.params, rlwe.EvaluationKey{Rlk: sess.Rlk})
	se.Evaluator = eval
	se.Environment = s.Environment

	dummyCtx := newCircuitParserCtx(id, se.params, nodeMapping)
	if err := cDef(dummyCtx); err != nil {
		panic(err)
	}
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

	se.protos = make(map[pkg.ProtocolID]protocols.KeySwitchInstance)

	for protoID, protoDesc := range se.cDesc.KeyOps {
		var aggregator pkg.NodeID
		if agg, hasAgg := protoDesc.Args["aggregator"]; hasAgg {
			aggregator = pkg.NodeID(agg.(string))
		} else {
			aggregator = pkg.NodeID(protoDesc.Args["target"].(string)) // TODO: check that aggregator is full node
		}

		protoDesc.Aggregator = aggregator
		protoDesc.Participants = sess.Nodes
		protoDesc.Receivers = []pkg.NodeID{aggregator}
		proto, err := protocols.NewProtocol(protoDesc, sess, protoID)
		if err != nil {
			panic(err)
		}
		if err = se.RegisterProtocol(protoID, protoDesc.Type); err != nil {
			panic(err)
		}
		se.protos[protoID], _ = proto.(protocols.KeySwitchInstance)
	}

	peerInt := make(map[pkg.NodeID]services.ProtocolClient)
	for peerID, peerCli := range peers {
		peerInt[peerID] = peerCli
	}
	se.Environment.Connect(peerInt)

	se.inputs, se.outputs = make(chan pkg.Operand, len(se.cDesc.InputSet)), make(chan pkg.Operand, len(se.cDesc.OutputSet))

	se.f = cDef

	return se
}

func (se *fullEvaluatorContext) Execute(ctx context.Context) error {

	log.Printf("Node %s | started full context Execute of %s\n", se.sess.NodeID, se.id)

	se.Environment.Run(ctx)

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

	cksInt := se.protos[id]

	cksInt.Input(in.Ciphertext)

	cksInt.Run(context.Background(), se.sess, se.EnvironmentForProtocol(id))

	if utils.NewSet(cksInt.Desc().Receivers).Contains(se.sess.NodeID) {
		out = pkg.Operand{Ciphertext: <-cksInt.Output()}
	}

	out.OperandLabel = pkg.OperandLabel(fmt.Sprintf("//%s/%s-out-0", params["target"], id))

	return out, nil
}

func (se *fullEvaluatorContext) PCKS(id pkg.ProtocolID, in pkg.Operand, params map[string]interface{}) (out pkg.Operand, err error) {
	se.Set(in)

	cksInt := se.protos[id]

	cksInt.Input(in.Ciphertext)

	cksInt.Run(context.Background(), se.sess, se.EnvironmentForProtocol(id))

	if utils.NewSet(cksInt.Desc().Receivers).Contains(se.sess.NodeID) {
		out = pkg.Operand{Ciphertext: <-cksInt.Output()}
	}

	out.OperandLabel = pkg.OperandLabel(fmt.Sprintf("//%s/%s-out-0", params["target"], id))
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

			inURL := NewURL(string(in))
			if len(inURL.Host) == 0 || inURL.Host == string(se.sess.NodeID) {
				log.Printf("Node %s | skipping input %s\n", se.sess.NodeID, in)
				continue
			}

			peer, hasCli := se.peers[inURL.NodeID()]
			if !hasCli {
				continue // TODO should be a better way to check if peer is a light node
			}

			outctx := pkg.GetOutgoingContext(ctx, se.sess.NodeID)
			resp, err := peer.GetCiphertext(outctx, &api.CiphertextRequest{Id: inURL.CiphertextID().ToGRPC()})
			if err != nil {
				panic(err)
			}

			var ct *pkg.Ciphertext
			ct, err = pkg.NewCiphertextFromGRPC(resp)
			if err != nil {
				panic(status.Errorf(codes.InvalidArgument, "invalid ciphertext: %s", err))
			}
			op = pkg.Operand{OperandLabel: in, Ciphertext: &ct.Ciphertext}
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
