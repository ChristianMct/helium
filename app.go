package helium

import (
	"context"
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// App is a Helium application: the MHE setup it requires, the circuits it can
// evaluate, and the Main function that every node runs.
type App struct {
	// Setup describes the MHE setup required by the application.
	Setup *SetupDescription
	// Circuits is the library of circuits of the application.
	Circuits map[Name]Circuit
	// Main is the application's function, run by every node once the setup phase has
	// started. It evaluates circuits and runs protocols through the Runtime; a node
	// takes part only in the circuits and protocols its Main requests. A nil Main only
	// takes part in the setup phase.
	Main func(ctx context.Context, rt Runtime) error
}

// Runtime is the interface of the framework available to an application's Main
// function. It lets the application evaluate circuits and run decryption protocols;
// its methods block until the corresponding circuit or protocol has terminated.
//
// All the nodes run the same Main function, and a node takes part in a circuit or a
// protocol only once its Main has requested it: the coordination events of a circuit
// or protocol in which the node has a role are held until the matching Runtime call.
// On the coordinating node, the calls also start the circuits and protocols.
type Runtime interface {
	// ID returns the id of the node running the application.
	ID() NodeID

	// Session returns the session state of the node.
	Session() *Session

	// Parameters returns the FHE parameters of the session.
	Parameters() FHEParameters

	// IsCoordinator returns whether the node coordinates the circuits and protocols.
	IsCoordinator() bool

	// Evaluate evaluates the circuit described by cd and returns references to its
	// outputs, by name. The inputs are the node's inputs to the circuit, by input name
	// (the name part of the node's input ports, or the name of a summed input):
	// plaintext values ([]uint64, []int64 for BGV, []float64, []complex128 for CKKS),
	// *rlwe.Plaintext, *rlwe.Ciphertext or OperandRef. The method blocks until the
	// circuit has terminated at this node.
	Evaluate(ctx context.Context, cd Descriptor, inputs map[string]any) (map[string]OperandRef, error)

	// Decrypt runs the decryption protocol of operand op towards the target node, with
	// the given smudging noise (in bits). It blocks until the protocol has completed,
	// and returns the plaintext at the target node (nil elsewhere).
	Decrypt(ctx context.Context, op OperandRef, target NodeID, smudging float64) (*rlwe.Plaintext, error)

	// Operand returns a reference to the operand with the given id.
	Operand(id OperandID) OperandRef

	// Logf logs a message with the node's prefix.
	Logf(format string, args ...any)
}

// OperandRef is a reference to a system-wide operand (an input or an output of a
// circuit). Its ciphertext is fetched lazily from the node owning it.
type OperandRef struct {
	ID OperandID

	fetch func(ctx context.Context, id OperandID) (*Operand, error)
}

// NewOperandRef returns a reference to the operand with the given id, whose ciphertext
// is obtained by calling fetch. It is meant to be used by the node implementations.
func NewOperandRef(id OperandID, fetch func(ctx context.Context, id OperandID) (*Operand, error)) OperandRef {
	return OperandRef{ID: id, fetch: fetch}
}

// Get returns the ciphertext of the operand, fetching it from its owner if necessary.
func (op OperandRef) Get(ctx context.Context) (*rlwe.Ciphertext, error) {
	if op.fetch == nil {
		return nil, fmt.Errorf("operand %s is not bound to a runtime", op.ID)
	}
	o, err := op.fetch(ctx, op.ID)
	if err != nil {
		return nil, err
	}
	return o.Ciphertext, nil
}
