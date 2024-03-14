// Package circuits provides the types and interfaces for defining, parsing and executing circuits.
package circuits

import (
	"fmt"

	"github.com/ldsec/helium"
	"github.com/ldsec/helium/protocols"
	"github.com/ldsec/helium/utils"
	"github.com/tuneinsight/lattigo/v4/bgv"
	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe/ringqp"
)

// Circuit is a type for representing circuits, which are Go functions interacting with
// a provided evaluation runtime.
type Circuit func(Runtime) error

// Runtime defines the interface that is available to circuits to access
// their execution context.
type Runtime interface {
	// Input reads an input operand with the given label from the context.
	// When specifying the label, the user:
	//  - can use a placeholder id for the node, the mapping for which is provided in the Signature.
	//  - can omit the session-id part as it wil be automatically resolved by the runtime.
	Input(OperandLabel) *FutureOperand

	// Load reads an existing ciphertext in the session
	// When specifying the label, the user:
	//  - can use a placeholder id for the node, the mapping for which is provided in the Signature.
	//  - can omit the session-id part as it wil be automatically resolved by the runtime.
	Load(OperandLabel) *Operand

	// NewOperand creates a new operand with the given label.
	// When specifying the label, the user:
	//  - can use a placeholder id for the node, the mapping for which is provided in the Signature.
	//  - can omit the session-id part as it wil be automatically resolved by the runtime.
	NewOperand(OperandLabel) Operand

	// DEC performes the decryption of in, with private output to rec.
	// The decrypted operand is considered an output for the this circuit and the
	// given reciever.
	// It expect the users to provide the decryption parameters, including the level
	// at which the operation is performed and the smudging parameter.
	DEC(in Operand, rec helium.NodeID, params map[string]string) error

	// PCKS performes the re-encryption of in to the public key of rec.
	// The the re-encrypted operand is considered an output for the this circuit and the
	// given reciever.
	// It expect the users to provide the key-switch parameters, including the level
	// at which the operation is performed and the smudging parameter.
	PCKS(in Operand, rec helium.NodeID, params map[string]string) error

	// Parameters returns the encryption parameters for the circuit.
	Parameters() bgv.Parameters

	// NewEvaluator returns a new evaluator to be used in this circuit.
	NewEvaluator() Evaluator

	Evaluator
}

// Name is a type for circuit names.
// A circuit name is a string that uniquely identifies a circuit within the framework.
// Multiple instances of the same circuit can exist within the system (see circuits.ID).
type Name string

// Signature is a type for circuit signatures.
// A circuit signature is akin to a function signature in a programming language:
// it associates the name of the circuit with a set of arguments.
type Signature struct {
	Name
	Args map[string]string
}

// Descriptor is a struct for specifying a circuit execution.
// It holds the identification information for the circuit, as well as a concrete mapping from the
// node ids in the circuit definition.
type Descriptor struct {
	Signature
	helium.CircuitID
	NodeMapping map[string]helium.NodeID
	Evaluator   helium.NodeID
}

// Metadata is a type for gathering information about a circuit instance.
// It is obtained by parsing a circuit defintion (see circuits.Parse)
type Metadata struct {
	Descriptor
	InputSet, Ops, OutputSet utils.Set[OperandLabel]
	InputsFor, OutputsFor    map[helium.NodeID]utils.Set[OperandLabel]
	KeySwitchOps             map[string]protocols.Signature
	NeedRlk                  bool
	GaloisKeys               utils.Set[uint64]
}

// Event is a type for circuit-related events.
type Event struct {
	EventType
	Descriptor
}

// EventType define the type of event (see circuits.Event)
type EventType int8

const (
	// Completed corresponds to then event of a circuit being completed.
	// It is emitted zero (failure) or one time per circuit instance.
	Completed EventType = iota
	// Started corresponds to then event of a circuit being started.
	// It is emitted once per circuit instance.
	Started
	// Executing is an event type for execution-related events.
	// This event tpe can be emitted multiple times per circuit instance,
	// for example, at each protocol Event.
	Executing
	// Failed corresponds to then event of a circuit failing to execute to completion.
	Failed
)

// Output is a type for circuit outputs. It associates the output operand with the ID of the circuit that has produced it.
type Output struct {
	helium.CircuitID
	Operand
}

// Evaluator is an interface that is directly supported by circuit runtimes.
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

var statusToString = []string{"COMPLETED", "STARTED", "EXECUTING", "FAILED"}

func (t EventType) String() string {
	if int(t) > len(statusToString) {
		t = 0
	}
	return statusToString[t]
}

func (u Event) String() string {
	return fmt.Sprintf("%s: %s", u.EventType, u.Descriptor)
}
