package circuit

import (
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/ChristianMct/helium"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
)

// Operand is a type for representing circuit operands.
// Each operand within a circuit must have a unique label.
type Operand struct {
	OperandLabel
	*rlwe.Ciphertext
}

// OperandLabel is a type operand labels. Operand labels have the following format:
//
//	//<node-id>/<circuit-id>/<ciphertext-id>
//
// where:
//   - node-id is the id of the node that owns the operand,
//   - circuit-id is the id of the circuit in which this operand is used,
//   - ciphertext-id is the id of the ciphertext within the circuit.
//
// The circuit-id part is optional and can be omitted (1) in the context of a circuit definition, where it
// will be automatically expanded by the framework and (2) in the context of a global ciphertext that is
// available session-wide.
type OperandLabel string

// FutureOperand is a type for operands for which the actual ciphertext
// is not known yet and will be set later. It enables waiting on operands.
type FutureOperand struct {
	Operand
	c chan struct{}
}

// NewFutureOperand creates a new future operand with the given label.
func NewFutureOperand(opl OperandLabel) *FutureOperand {
	return &FutureOperand{Operand: Operand{OperandLabel: opl}, c: make(chan struct{})}
}

// NewDummyFutureOperand creates a new future operand with the given label, but for which
// the ciphertext is immediatly set to nil. It is used in the context of circuit parsing.
func NewDummyFutureOperand(opl OperandLabel) *FutureOperand {
	c := make(chan struct{})
	close(c)
	return &FutureOperand{Operand: Operand{OperandLabel: opl}, c: c}
}

// Set sets the actual ciphertext for the future operand and unlocks the routines waiting
// in the Get method.
func (fo *FutureOperand) Set(op Operand) {
	if fo.Ciphertext != nil { // TODO that only the main circuit routine calls set
		return
	}
	fo.Ciphertext = op.Ciphertext
	close(fo.c)
}

// Get returns the actual operand, waiting for the ciphertext to be set if necessary.
func (fo *FutureOperand) Get() Operand {
	<-fo.c
	return fo.Operand
}

// NodeID returns the node id part of the operand label.
func (opl OperandLabel) NodeID() helium.NodeID {
	nopl, err := url.Parse(string(opl))
	if err != nil {
		panic(fmt.Errorf("invalid operand label: %s", opl))
	}
	return helium.NodeID(nopl.Host)
}

// CircuitID returns the circuit id part of the operand label.
func (opl OperandLabel) CircuitID() helium.CircuitID {
	nopl, err := url.Parse(string(opl))
	if err != nil {
		panic(fmt.Errorf("invalid operand label: %s", opl))
	}
	return helium.CircuitID(strings.Trim(path.Dir(nopl.Path), "/"))
}

// HasNode returns true if the operand label has the given host id.
func (opl OperandLabel) HasNode(id helium.NodeID) bool {
	nopl, err := url.Parse(string(opl))
	if err != nil {
		panic(fmt.Errorf("invalid operand label: %s", opl))
	}
	return nopl.Host == string(id)
}

// ForCircuit returns a new operand label for the given circuit id, with
// the circuit id part set to cid.
func (opl OperandLabel) ForCircuit(cid helium.CircuitID) OperandLabel {
	nopl, err := url.Parse(string(opl))
	if err != nil {
		panic(fmt.Errorf("invalid operand label: %s", opl))
	}
	nopl.Path = fmt.Sprintf("/%s%s", cid, nopl.Path)
	return OperandLabel(nopl.String())
}

// ForMapping returns a new operand label with the node id part replaced by the
// corresponding value in the provided mapping.
func (opl OperandLabel) ForMapping(nodeMapping map[string]helium.NodeID) OperandLabel {
	if nodeMapping == nil {
		return opl
	}
	nopl, err := url.Parse(string(opl))
	if err != nil {
		panic(fmt.Errorf("invalid operand label: %s", opl))
	}
	if len(nopl.Host) > 0 {
		nodeID, provided := nodeMapping[nopl.Host]
		if !provided {
			panic(fmt.Errorf("no mapping provided for node id %s", nopl.Host))
		}
		nopl.Host = string(nodeID)
	}
	return OperandLabel(nopl.String())
}
