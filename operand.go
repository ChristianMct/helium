package helium

import (
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
)

// OperandID is the system-wide identifier of an operand. Operand ids have the URL form
//
//	//<node-id>/<circuit-id>/<name>
//
// where node-id is the node owning the operand (the provider of an input, the evaluator
// of an output), circuit-id is the id of the circuit evaluation the operand belongs to,
// and name is the name of the port within the circuit.
type OperandID string

// NewOperandID builds the operand id for the given owner, circuit and name.
func NewOperandID(owner NodeID, cid CircuitID, name string) OperandID {
	return OperandID(fmt.Sprintf("//%s/%s/%s", owner, cid, name))
}

func (id OperandID) parse() (owner NodeID, cid CircuitID, name string, err error) {
	u, err := url.Parse(string(id))
	if err != nil {
		return "", "", "", fmt.Errorf("invalid operand id %q: %w", id, err)
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(u.Host) == 0 || len(parts) != 2 || len(parts[0]) == 0 || len(parts[1]) == 0 {
		return "", "", "", fmt.Errorf("invalid operand id %q: must be of the form //<node-id>/<circuit-id>/<name>", id)
	}
	return NodeID(u.Host), CircuitID(parts[0]), parts[1], nil
}

// Validate returns an error if the operand id is not well-formed.
func (id OperandID) Validate() error {
	_, _, _, err := id.parse()
	return err
}

// NodeID returns the id of the node owning the operand.
func (id OperandID) NodeID() NodeID {
	owner, _, _, _ := id.parse()
	return owner
}

// CircuitID returns the id of the circuit evaluation the operand belongs to.
func (id OperandID) CircuitID() CircuitID {
	_, cid, _, _ := id.parse()
	return cid
}

// Name returns the name of the operand within its circuit.
func (id OperandID) Name() string {
	_, _, name, _ := id.parse()
	return name
}

// Operand is an identified ciphertext.
type Operand struct {
	ID OperandID
	*rlwe.Ciphertext
}

// FutureOperand is an operand whose ciphertext may not be known yet.
// It enables waiting on operands.
type FutureOperand struct {
	id   OperandID
	ct   *rlwe.Ciphertext
	c    chan struct{}
	once sync.Once
}

// NewFutureOperand creates a new future operand with the given id.
func NewFutureOperand(id OperandID) *FutureOperand {
	return &FutureOperand{id: id, c: make(chan struct{})}
}

// ID returns the id of the operand.
func (fo *FutureOperand) ID() OperandID {
	return fo.id
}

// Set sets the ciphertext of the future operand and unblocks the routines waiting in Get.
// Only the first call has an effect.
func (fo *FutureOperand) Set(ct *rlwe.Ciphertext) {
	fo.once.Do(func() {
		fo.ct = ct
		close(fo.c)
	})
}

// Get returns the operand, waiting for its ciphertext to be set if necessary.
func (fo *FutureOperand) Get() Operand {
	<-fo.c
	return Operand{ID: fo.id, Ciphertext: fo.ct}
}

// Done returns a channel that is closed when the operand is set.
func (fo *FutureOperand) Done() <-chan struct{} {
	return fo.c
}

// OutputOperand is a handle on an output of a circuit, to be set by the circuit
// once computed.
type OutputOperand struct {
	id OperandID
	mu sync.Mutex
	ct *rlwe.Ciphertext
}

// NewOutputOperand creates a new output operand handle with the given id.
func NewOutputOperand(id OperandID) *OutputOperand {
	return &OutputOperand{id: id}
}

// ID returns the id of the output operand.
func (oo *OutputOperand) ID() OperandID {
	return oo.id
}

// Set sets the ciphertext of the output.
func (oo *OutputOperand) Set(ct *rlwe.Ciphertext) {
	oo.mu.Lock()
	defer oo.mu.Unlock()
	oo.ct = ct
}

// Get returns the output operand and whether it has been set.
func (oo *OutputOperand) Get() (Operand, bool) {
	oo.mu.Lock()
	defer oo.mu.Unlock()
	return Operand{ID: oo.id, Ciphertext: oo.ct}, oo.ct != nil
}
