// Package circuits provides the types and interfaces for defining, parsing and executing circuits.
package circuits

import (
	"context"
	"fmt"

	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/sessions"
	"github.com/ChristianMct/helium/utils"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he"
)

// Circuit is a type for representing circuits, which are Go functions interacting with
// a provided evaluation runtime.
type Circuit func(Runtime) error

// Runtime defines the interface that is available to circuits to access
// their execution context.
type Runtime interface {
	Parameters() sessions.FHEParameters

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
	NewOperand(OperandLabel) *Operand

	// EvalLocal is used to perform local operation on the ciphertext. This is where the FHE computation
	// is performed. The user must specify the required evaluation keys needed by the function. The provided
	// function must not call any other Runtime function (ie., it must be  strictly local circuit).
	EvalLocal(needRlk bool, galKeys []uint64, f func(he.Evaluator) error) error

	// DEC performes the decryption of in, with private output to rec.
	// The decrypted operand is considered an output for the this circuit and the
	// given reciever.
	// It expect the users to provide the decryption parameters, including the level
	// at which the operation is performed and the smudging parameter.
	DEC(in Operand, rec sessions.NodeID, params map[string]string) error

	// PCKS performes the re-encryption of in to the public key of rec.
	// The the re-encrypted operand is considered an output for the this circuit and the
	// given reciever.
	// It expect the users to provide the key-switch parameters, including the level
	// at which the operation is performed and the smudging parameter.
	PCKS(in Operand, rec sessions.NodeID, params map[string]string) error
}

// PublicKeyProvider is an interface for querying public encryption- and evaluation-keys.
// The setup service is a notable implementation of this interface.
type PublicKeyProvider interface {
	GetCollectivePublicKey(context.Context) (*rlwe.PublicKey, error)
	GetGaloisKey(ctx context.Context, galEl uint64) (*rlwe.GaloisKey, error)
	GetRelinearizationKey(context.Context) (*rlwe.RelinearizationKey, error)
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
	sessions.CircuitID
	NodeMapping map[string]sessions.NodeID
	Evaluator   sessions.NodeID
}

// Metadata is a type for gathering information about a circuit instance.
// It is obtained by parsing a circuit defintion (see circuits.Parse)
type Metadata struct {
	Descriptor
	InputSet, Ops, OutputSet utils.Set[OperandLabel]
	InputsFor, OutputsFor    map[sessions.NodeID]utils.Set[OperandLabel]
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
	sessions.CircuitID
	Operand
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
