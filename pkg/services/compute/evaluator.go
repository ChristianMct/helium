package compute

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"sync"

	"github.com/ldsec/helium/pkg/protocols"
	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/ldsec/helium/pkg/transport"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

// ServiceEvaluationEnvironment defines the interface that is available to the service
// to access evaluation contexts of a particular circuit evaluation.
type ServiceEvaluationEnvironment interface {

	// CircuitDescription returns the CircuitDescription for the circuit executing within this context.
	CircuitDescription() CircuitDescription

	// LocalInput provides the local inputs to the circuit executing within this context.
	LocalInputs([]pkg.Operand) error

	IncomingInput(pkg.Operand) error

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

	isLight map[pkg.NodeID]bool

	transport transport.ComputeServiceTransport

	sess   *pkg.Session
	params bfv.Parameters
	id     pkg.CircuitID

	outgoingOps, ops, inputOps map[pkg.OperandLabel]*FutureOperand

	protos map[pkg.ProtocolID]protocols.KeySwitchInstance

	inputs, outputs chan pkg.Operand

	f     Circuit
	cDesc CircuitDescription

	// TODO Extract ProtocolRunner
	runningProtosMu sync.RWMutex
	runningProtos   map[pkg.ProtocolID]struct {
		pd       protocols.Descriptor
		incoming chan protocols.Share
	}
}

// newFullEvaluationContext creates a new full-evaluator context used by aggregators to execute a circuit.
func (s *Service) newFullEvaluationContext(sess *pkg.Session, id pkg.CircuitID, cDef Circuit, nodeMapping map[string]pkg.NodeID) *fullEvaluatorContext {
	se := new(fullEvaluatorContext)
	se.id = id
	se.sess = sess

	se.params, _ = bfv.NewParameters(*sess.Params, 65537)

	se.isLight = make(map[pkg.NodeID]bool)

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
		in := pkg.NewURL(string(inLabel))
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

	for protoID, protoDesc := range se.cDesc.KeySwitchOps {
		var aggregator pkg.NodeID
		if agg, hasAgg := protoDesc.Args["aggregator"]; hasAgg {
			aggregator = pkg.NodeID(agg)
		} else {
			aggregator = pkg.NodeID(protoDesc.Args["target"]) // TODO: check that aggregator is full node
		}

		protoDesc.Aggregator = aggregator

		part := utils.NewSet(sess.Nodes)
		if protoDesc.Type == protocols.DEC {
			part.Remove(pkg.NodeID(protoDesc.Args["target"]))
		}

		protoDesc.Participants = part.Elements() // TODO decide on exec
		proto, err := protocols.NewProtocol(protoDesc, sess, protoID)
		if err != nil {
			panic(err)
		}
		se.protos[protoID], _ = proto.(protocols.KeySwitchInstance)
	}

	se.inputs, se.outputs = make(chan pkg.Operand, len(se.cDesc.InputSet)), make(chan pkg.Operand, len(se.cDesc.OutputSet))

	se.f = cDef

	se.transport = s.transport
	// TODO extract protocolrunner

	se.runningProtos = make(map[pkg.ProtocolID]struct {
		pd       protocols.Descriptor
		incoming chan protocols.Share
	})
	go func() {
		for incShare := range se.transport.IncomingShares() {
			se.runningProtosMu.RLock()
			proto, exists := se.runningProtos[incShare.ProtocolID]
			se.runningProtosMu.RUnlock()
			if !exists {
				panic("protocol is not running")
			}
			proto.incoming <- incShare
		}
	}()

	return se
}

func (se *fullEvaluatorContext) Execute(ctx context.Context) error {

	log.Printf("%s | started full context Execute of %s\n", se.sess.NodeID, se.id)

	rlk := new(rlwe.RelinearizationKey)
	if se.cDesc.NeedRlk {
		err := se.sess.ObjectStore.Load(protocols.Signature{Type: protocols.RKG}.String(), rlk)
		if err != nil {
			panic(fmt.Errorf("%s | rlk was not found for node %s: %s", se.sess.NodeID, se.sess.NodeID, err))
		}
	}

	rtks := rlwe.NewRotationKeySet(se.params.Parameters, se.cDesc.GaloisKeys.Elements())
	for galEl := range se.cDesc.GaloisKeys {
		err := se.sess.ObjectStore.Load(protocols.Signature{Type: protocols.RTG, Args: map[string]string{"GalEl": strconv.FormatUint(galEl, 10)}}.String(), rtks.Keys[galEl])
		if err != nil {
			panic(fmt.Errorf("%s | rtk for galEl %d was not found: %s", se.sess.NodeID, galEl, err))
		}
	}

	eval := bfv.NewEvaluator(se.params, rlwe.EvaluationKey{Rlk: rlk, Rtks: rtks})
	se.Evaluator = eval

	se.resolveRemoteInputs(ctx, se.cDesc.InputSet)

	err := se.f(se)

	close(se.outputs)
	log.Printf("%s | full context Execute returned, err = %v \n", se.sess.NodeID, err)

	return err
}

func (se *fullEvaluatorContext) LocalInputs(lops []pkg.Operand) error {
	for _, lop := range lops {
		se.inputs <- lop // TODO validate
	}
	return nil
}

func (se *fullEvaluatorContext) IncomingInput(op pkg.Operand) error {
	se.inputs <- op
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
	log.Printf("%s | got input %s\n", se.sess.NodeID, op.OperandLabel)
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

func (se *fullEvaluatorContext) Output(op pkg.Operand, to pkg.NodeID) {
	se.ops[op.OperandLabel.ForCircuit(se.id)].Done(op)
	se.outputs <- pkg.Operand{OperandLabel: op.OperandLabel.ForCircuit(se.id), Ciphertext: op.Ciphertext}
}

func (se *fullEvaluatorContext) SubCircuit(_ pkg.CircuitID, _ Circuit) (EvaluationContext, error) {
	panic("not implemented") // TODO: Implement
}

func (se *fullEvaluatorContext) CKS(id pkg.ProtocolID, in pkg.Operand, params map[string]string) (out pkg.Operand, err error) {
	return se.runKeySwitch(id, in, params)
}

func (se *fullEvaluatorContext) PCKS(id pkg.ProtocolID, in pkg.Operand, params map[string]string) (out pkg.Operand, err error) {
	return se.runKeySwitch(id, in, params)
}

func (se *fullEvaluatorContext) runKeySwitch(id pkg.ProtocolID, in pkg.Operand, params map[string]string) (out pkg.Operand, err error) {
	se.Set(in)

	_ = params // TODO will need this for dynamic participant sets

	cksInt := se.protos[id]

	incShares := make(chan protocols.Share)
	se.runningProtosMu.Lock()
	se.runningProtos[id] = struct {
		pd       protocols.Descriptor
		incoming chan protocols.Share
	}{cksInt.Desc(), incShares}
	se.runningProtosMu.Unlock()

	cksInt.Input(in.Ciphertext)

	agg := <-cksInt.Aggregate(context.Background(), se.sess, &ProtocolEnvironment{incoming: incShares, outgoing: se.transport.OutgoingShares()})
	if agg.Error != nil {
		return pkg.Operand{}, agg.Error
	}

	out = pkg.Operand{Ciphertext: (<-cksInt.Output(agg)).Result.(*rlwe.Ciphertext)}

	out.OperandLabel = pkg.OperandLabel(fmt.Sprintf("%s-%s-out", in.OperandLabel, id))
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

			// DEBUG
			//log.Printf("[ResolveRemoteInputs] fetching %v", in)
			var op pkg.Operand

			inURL := pkg.NewURL(string(in))
			if len(inURL.Host) == 0 || inURL.Host == string(se.sess.NodeID) {
				continue
			}

			if se.isLight[inURL.NodeID()] {
				continue // skipping light node inputs coming in push mode
			}

			ctx = pkg.NewContext(&se.sess.ID, &se.id) // TODO: derive from passed context

			ct, err := se.transport.GetCiphertext(ctx, pkg.CiphertextID(in))
			if err != nil {
				log.Printf("%s | could not resolve input %s: %s", se.sess.NodeID, in, err)
				continue
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
