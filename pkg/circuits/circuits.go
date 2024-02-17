package circuits

import (
	"fmt"

	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v4/bgv"
	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe/ringqp"
	"golang.org/x/exp/maps"
)

type Name string

type ID string

type Signature struct {
	Name
	Args map[string]string
}

type Descriptor struct {
	Signature
	ID
	InputParties map[string]pkg.NodeID
	Evaluator    pkg.NodeID
}

type Status int32 // TODO harmonize with protocols.Event

const (
	Completed Status = iota
	Started
	Executing
	Failed
)

type Event struct {
	Status
	Descriptor
}

// Circuit is a type for representing circuits, which are go functions interacting with
// a provided evaluation context.
type Circuit func(EvaluationContext) error

// EvaluationContext defines the interface that is available to circuits to access
// their execution context.
type EvaluationContext interface {
	// Input reads an input operand with the given label from the context.
	Input(OperandLabel) FutureOperand

	// Load reads an existing ciphertext in the session
	Load(OperandLabel) Operand

	// Set registers the given operand to the context.
	Set(Operand)

	// Output outputs the given operand to the context.
	Output(Operand, pkg.NodeID)

	// DEC runs a DEC protocol over the provided operand within the context.
	DEC(in Operand, params map[string]string) (out *FutureOperand, err error)

	// PCKS runs a PCKS protocol over the provided operand within the context.
	PCKS(in Operand, params map[string]string) (out *FutureOperand, err error)

	// Parameters returns the encryption parameters for the circuit.
	Parameters() bgv.Parameters

	NewEvaluator() Evaluator

	//EvalWithKey(evk rlwe.EvaluationKeySet) Evaluator

	Evaluator
}

type Evaluator interface {
	Add(op0 *rlwe.Ciphertext, op1 interface{}, opOut *rlwe.Ciphertext) (err error)
	Sub(op0 *rlwe.Ciphertext, op1 interface{}, opOut *rlwe.Ciphertext) (err error)
	Mul(op0 *rlwe.Ciphertext, op1 interface{}, opOut *rlwe.Ciphertext) (err error)
	MulNew(op0 *rlwe.Ciphertext, op1 interface{}) (opOut *rlwe.Ciphertext, err error)
	MulRelin(op0 *rlwe.Ciphertext, op1 interface{}, opOut *rlwe.Ciphertext) (err error)
	MulRelinNew(op0 *rlwe.Ciphertext, op1 interface{}) (opOut *rlwe.Ciphertext, err error)
	MulThenAdd(op0 *rlwe.Ciphertext, op1 interface{}, opOut *rlwe.Ciphertext) (err error)
	Relinearize(op0, op1 *rlwe.Ciphertext) (err error)
	Rescale(op0, op1 *rlwe.Ciphertext) (err error)
	InnerSum(ctIn *rlwe.Ciphertext, batchSize, n int, opOut *rlwe.Ciphertext) (err error)
	AutomorphismHoisted(level int, ctIn *rlwe.Ciphertext, c1DecompQP []ringqp.Poly, galEl uint64, opOut *rlwe.Ciphertext) (err error)

	DecomposeNTT(levelQ, levelP, nbPi int, c2 ring.Poly, c2IsNTT bool, decompQP []ringqp.Poly)
	NewDecompQPBuffer() []ringqp.Poly
}

func (cd Descriptor) InputPartiesIDSet() utils.Set[pkg.NodeID] {
	return utils.NewSet(maps.Values(cd.InputParties))
}

var statusToString = []string{"COMPLETED", "STARTED", "EXECUTING", "FAILED"}

func (t Status) String() string {
	if int(t) > len(statusToString) {
		t = 0
	}
	return statusToString[t]
}

func (u Event) String() string {
	return fmt.Sprintf("%s: %s", u.Status, u.Descriptor)
}
