package compute

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/protocols"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v4/bgv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

// CircuitInstance defines the interface that is available to the service
// to access evaluation contexts of a particular circuit evaluation.
type CircuitInstance interface {

	// CircuitDescription returns the CircuitDescription for the circuit executing within this context.
	CircuitDescription() CircuitDescription

	// LocalInput provides the local inputs to the circuit executing within this context.
	LocalInputs([]pkg.Operand) error

	IncomingOperand(pkg.Operand) error

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
	*bgv.Evaluator

	service *Service
	sess    *pkg.Session
	pkbk    PublicKeyBackend
	params  bgv.Parameters
	cid     pkg.CircuitID

	outgoingOps, ops, inputOps map[pkg.OperandLabel]*FutureOperand

	inputs, outputs chan pkg.Operand

	f     Circuit
	cDesc CircuitDescription
}

// newFullEvaluationContext creates a new full-evaluator context used by aggregators to execute a circuit.
func (s *Service) newFullEvaluationContext(sess *pkg.Session, pkbk PublicKeyBackend, id pkg.CircuitID, cDef Circuit, nodeMapping map[string]pkg.NodeID) *fullEvaluatorContext {
	se := new(fullEvaluatorContext)
	se.cid = id
	se.sess = sess
	se.pkbk = pkbk
	se.service = s

	var err error
	se.params, err = bgv.NewParameters(*sess.Params, 65537)
	if err != nil {
		panic(err)
	}

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

	se.inputs, se.outputs = make(chan pkg.Operand, len(se.cDesc.InputSet)), make(chan pkg.Operand, len(se.cDesc.OutputSet))

	se.f = cDef

	return se
}

func (se *fullEvaluatorContext) Execute(ctx context.Context) error {

	log.Printf("%s | started full context Execute of %s\n", se.sess.NodeID, se.cid)

	var err error
	rlk := new(rlwe.RelinearizationKey)
	if se.cDesc.NeedRlk {
		rlk, err = se.pkbk.GetRelinearizationKey()
		if err != nil {
			panic(fmt.Errorf("%s | %s", se.sess.NodeID, err))
		}
	}

	gks := make([]*rlwe.GaloisKey, 0, len(se.cDesc.GaloisKeys))
	for galEl := range se.cDesc.GaloisKeys {
		var err error
		gk, err := se.GetGaloisKey(galEl)
		if err != nil {
			panic(fmt.Errorf("%s | %s", se.sess.NodeID, err))
		}
		gks = append(gks, gk)
	}

	//rtks := rlwe.NewRotationKeySet(se.params.Parameters, se.cDesc.GaloisKeys.Elements())
	evk := rlwe.NewMemEvaluationKeySet(rlk, gks...)
	eval := bgv.NewEvaluator(se.params, evk)
	se.Evaluator = eval

	eval.ShallowCopy()

	se.resolveRemoteInputs(ctx, se.cDesc.InputSet)

	err = se.f(se)

	close(se.outputs)
	log.Printf("%s | %s | full context Execute returned, err = %v \n", se.sess.NodeID, se.cid, err)

	return err
}

func (se *fullEvaluatorContext) LocalInputs(lops []pkg.Operand) error {
	for _, lop := range lops {
		se.inputs <- lop // TODO validate
	}
	return nil
}

func (se *fullEvaluatorContext) IncomingOperand(op pkg.Operand) error {
	se.inputs <- op
	return nil
}

func (se *fullEvaluatorContext) LocalOutputs() chan pkg.Operand {
	return se.outputs
}

func (se *fullEvaluatorContext) Input(opl pkg.OperandLabel) pkg.Operand {
	fop, exists := se.inputOps[opl.ForCircuit(se.cid)]
	if !exists {
		panic(fmt.Errorf("unexpected input: %s", opl))
	}
	op := <-fop.Await()
	log.Printf("%s | got input %s\n", se.sess.NodeID, op.OperandLabel)
	return op
}

func (se *fullEvaluatorContext) Set(op pkg.Operand) {
	se.ops[op.OperandLabel.ForCircuit(se.cid)].Done(op)
}

func (se *fullEvaluatorContext) Get(opl pkg.OperandLabel) pkg.Operand {
	if fop, exists := se.ops[opl]; exists {
		return <-fop.Await()
	}
	panic(fmt.Errorf("Get on unknown op %s, %v", opl, se.ops))
}

func (se *fullEvaluatorContext) Output(op pkg.Operand, to pkg.NodeID) {
	se.ops[op.OperandLabel.ForCircuit(se.cid)].Done(op)
	se.outputs <- pkg.Operand{OperandLabel: op.OperandLabel.ForCircuit(se.cid), Ciphertext: op.Ciphertext}
}

func (se *fullEvaluatorContext) SubCircuit(_ pkg.CircuitID, _ Circuit) (EvaluationContext, error) {
	panic("not implemented") // TODO: Implement
}

func (se *fullEvaluatorContext) DEC(in pkg.Operand, params map[string]string) (out pkg.Operand, err error) {
	sig := GetProtocolSignature(protocols.DEC, in.OperandLabel.ForCircuit(se.cid), params)
	return se.runKeySwitch(sig, in)
}

func (se *fullEvaluatorContext) PCKS(in pkg.Operand, params map[string]string) (out pkg.Operand, err error) {
	sig := GetProtocolSignature(protocols.PCKS, in.OperandLabel.ForCircuit(se.cid), params)
	return se.runKeySwitch(sig, in)
}

func (se *fullEvaluatorContext) runKeySwitch(sig protocols.Signature, in pkg.Operand) (out pkg.Operand, err error) {
	se.Set(in)
	ctx := pkg.NewContext(&se.sess.ID, &se.cid)
	return se.service.RunKeySwitch(ctx, sig, in)
}

func (se *fullEvaluatorContext) Parameters() bgv.Parameters {
	return se.params
}

func (se *fullEvaluatorContext) NewEvaluator() Evaluator {
	return se.Evaluator.ShallowCopy()
}

func (se *fullEvaluatorContext) EvalWithKey(evk rlwe.EvaluationKeySet) Evaluator {
	return se.Evaluator.WithKey(evk)
}

func (se *fullEvaluatorContext) CircuitDescription() CircuitDescription {
	return se.cDesc
}

func (se *fullEvaluatorContext) resolveRemoteInputs(ctx context.Context, ins utils.Set[pkg.OperandLabel]) {

	// TODO parallel querying

	// fetches all inputs from full nodes
	// go func() {
	// 	for in := range ins {

	// 		var op pkg.Operand

	// 		inURL := pkg.NewURL(string(in))
	// 		if len(inURL.Host) == 0 || inURL.Host == string(se.sess.NodeID) {
	// 			continue
	// 		}

	// 		ctx = pkg.NewContext(&se.sess.ID, &se.id) // TODO: derive from passed context

	// 		ct, err := se.transport.GetCiphertext(ctx, pkg.CiphertextID(in))
	// 		if err != nil {
	// 			log.Printf("%s | could not resolve input %s: %s", se.sess.NodeID, in, err)
	// 			continue
	// 		}
	// 		op = pkg.Operand{OperandLabel: in, Ciphertext: &ct.Ciphertext}
	// 		se.inputs <- op
	// 	}
	// }()

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

// Done sets the future operand to op. Only the first
// call has an effect.
func (fop *FutureOperand) Done(op pkg.Operand) {
	fop.m.Lock()
	defer fop.m.Unlock()
	if fop.op != nil {
		return
	}
	fop.op = &op
	for _, aw := range fop.awaiters {
		aw <- op // TODO copy ?
		close(aw)
	}
}

func (fop *FutureOperand) IsSet() bool {
	fop.m.Lock()
	defer fop.m.Unlock()
	return fop.op == nil
}
