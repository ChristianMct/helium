// Package node implements the node-side runtime of a Helium application: the
// wiring of the protocol and circuit runners, and the rendez-vous between the
// application's Main function and the coordination events (see gate).
//
// The package is agnostic of the setting in which the node runs: the
// setting-specific packages (helper for the helper-assisted setting) provide the
// coordination and transport, and drive a Runtime through the Starter interface.
package node

import (
	"context"
	"fmt"
	"log"
	"slices"
	"strconv"
	"sync"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/circuits"
	"github.com/ChristianMct/helium/protocols"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
)

// Starter is implemented by the coordinating node to start circuits and protocols.
// A node that does not coordinate (a peer in the helper-assisted setting) passes a
// nil Starter: its Runtime calls are expectations, fulfilled by the coordinator's
// events.
type Starter interface {
	// StartCircuit requests the evaluation of the circuit described by cd.
	StartCircuit(ctx context.Context, cd helium.Descriptor) error
	// StartProtocol requests the execution of a protocol with the given signature.
	StartProtocol(ctx context.Context, sig protocols.Signature) error
}

// Runtime implements helium.Runtime over a protocols.Runner and a circuits.Runner.
//
// A node takes part in a circuit or a protocol only once the application's Main
// function has requested it: the coordination events of a circuit or protocol in
// which the node has a role are held by a gate until the matching Runtime call.
type Runtime struct {
	self helium.NodeID
	sess *helium.Session

	protocols *protocols.Runner
	circuits  *circuits.Runner
	protoGate *gate[protocols.Event]
	circGate  *gate[circuits.Event]
	starter   Starter // nil if the node is not the coordinator

	mu     sync.Mutex
	inputs map[helium.CircuitID]map[string]any
}

var _ helium.Runtime = (*Runtime)(nil)

// New creates the runtime of a node over the given runners. The starter is nil for
// nodes that do not coordinate the circuits and protocols.
func New(self helium.NodeID, sess *helium.Session, pr *protocols.Runner, cr *circuits.Runner, st Starter) *Runtime {
	rt := &Runtime{
		self:      self,
		sess:      sess,
		protocols: pr,
		circuits:  cr,
		starter:   st,
		inputs:    make(map[helium.CircuitID]map[string]any),
	}
	rt.protoGate = newGate(rt.protocolGatePolicy())
	rt.circGate = newGate(rt.circuitGatePolicy())
	cr.SetInputProvider(rt.provideInputs)
	return rt
}

// ID returns the id of the node running the application.
func (rt *Runtime) ID() helium.NodeID {
	return rt.self
}

// Session returns the session state of the node.
func (rt *Runtime) Session() *helium.Session {
	return rt.sess
}

// Parameters returns the FHE parameters of the session.
func (rt *Runtime) Parameters() helium.FHEParameters {
	return rt.sess.Params
}

// IsCoordinator returns whether the node coordinates the circuits and protocols.
func (rt *Runtime) IsCoordinator() bool {
	return rt.starter != nil
}

// Operand returns a reference to the operand with the given id.
func (rt *Runtime) Operand(id helium.OperandID) helium.OperandRef {
	return helium.NewOperandRef(id, rt.getOperand)
}

func (rt *Runtime) getOperand(ctx context.Context, id helium.OperandID) (*helium.Operand, error) {
	return rt.circuits.GetOperand(ctx, id)
}

// Evaluate evaluates the circuit described by cd and returns references to its outputs,
// by name. It blocks until the circuit has terminated at this node; on the coordinating
// node, it also starts the circuit.
func (rt *Runtime) Evaluate(ctx context.Context, cd helium.Descriptor, inputs map[string]any) (map[string]helium.OperandRef, error) {
	md, err := rt.circuits.Metadata(cd)
	if err != nil {
		return nil, fmt.Errorf("invalid circuit %s: %w", cd.HID(), err)
	}

	if md.IsParticipant(rt.self) {
		for _, id := range md.InputsOf[rt.self] {
			if _, has := inputs[id.Name()]; !has {
				return nil, fmt.Errorf("missing input %q for circuit %s", id.Name(), cd.HID())
			}
		}
		rt.mu.Lock()
		rt.inputs[cd.CircuitID] = inputs
		rt.mu.Unlock()
	}

	known, err := rt.circGate.claim(ctx, string(cd.CircuitID))
	if err != nil {
		return nil, err
	}
	if rt.starter != nil && !known {
		if err := rt.starter.StartCircuit(ctx, cd); err != nil {
			return nil, err
		}
	}

	if _, err := rt.circuits.AwaitCompleted(ctx, cd.CircuitID); err != nil {
		return nil, err
	}

	outs := make(map[string]helium.OperandRef, len(md.Outputs))
	for name, id := range md.Outputs {
		outs[name] = rt.Operand(id)
	}
	return outs, nil
}

// Decrypt runs the decryption protocol of operand op towards the target node, with the
// given smudging noise (in bits). It blocks until the protocol has completed, and returns
// the plaintext at the target node (nil elsewhere). On the coordinating node, it also
// starts the protocol.
func (rt *Runtime) Decrypt(ctx context.Context, op helium.OperandRef, target helium.NodeID, smudging float64) (*rlwe.Plaintext, error) {
	sig := protocols.Signature{Type: protocols.DEC, Args: map[string]string{
		"op":       string(op.ID),
		"target":   string(target),
		"smudging": strconv.FormatFloat(smudging, 'f', -1, 64),
	}}

	known, err := rt.protoGate.claim(ctx, sig.String())
	if err != nil {
		return nil, err
	}
	if rt.starter != nil && !known {
		if err := rt.starter.StartProtocol(ctx, sig); err != nil {
			return nil, err
		}
	}

	pd, err := rt.protocols.AwaitCompleted(ctx, sig)
	if err != nil {
		return nil, err
	}
	if target != rt.self {
		return nil, nil
	}
	return rt.protocols.DecryptOutput(ctx, pd)
}

// Logf logs a message with the node's prefix.
func (rt *Runtime) Logf(msg string, v ...any) {
	log.Printf("%s | [App] %s\n", rt.self, fmt.Sprintf(msg, v...))
}

// ProtocolCoordinator wraps a protocol coordinator with this runtime's gate: the
// events of the protocols in which the node has a role reach the protocol runner
// only once the application has requested them.
func (rt *Runtime) ProtocolCoordinator(coord protocols.Coordinator) protocols.Coordinator {
	return &gatedCoordinator[protocols.Event]{register: coord.Register, publish: coord.Publish, g: rt.protoGate}
}

// CircuitCoordinator wraps a circuit coordinator with this runtime's gate.
func (rt *Runtime) CircuitCoordinator(coord circuits.Coordinator) circuits.Coordinator {
	return &gatedCoordinator[circuits.Event]{register: coord.Register, publish: coord.Publish, g: rt.circGate}
}

// Finish signals the gates that the application is done: the gated streams end once
// their upstream coordination stream is also closed.
func (rt *Runtime) Finish() {
	rt.protoGate.finish()
	rt.circGate.finish()
}

// provideInputs is the circuits.InputProvider of the node's circuit runner: it provides the
// inputs given to Evaluate.
func (rt *Runtime) provideInputs(ctx context.Context, cd helium.Descriptor, ids []helium.OperandID) (<-chan circuits.Input, error) {
	rt.mu.Lock()
	inputs, has := rt.inputs[cd.CircuitID]
	rt.mu.Unlock()
	if !has {
		return nil, fmt.Errorf("no inputs for circuit %s", cd.HID())
	}

	in := make(chan circuits.Input, len(ids))
	defer close(in)
	for _, id := range ids {
		v, has := inputs[id.Name()]
		if !has {
			return nil, fmt.Errorf("missing input %q for circuit %s", id.Name(), cd.HID())
		}
		if op, isOp := v.(helium.OperandRef); isOp {
			ct, err := op.Get(ctx)
			if err != nil {
				return nil, fmt.Errorf("cannot get operand %s: %w", op.ID, err)
			}
			v = ct
		}
		in <- circuits.Input{ID: id, Value: v}
	}
	return in, nil
}

// protocolGatePolicy gates the compute protocols (e.g., DEC) in which the node has a role
// (aggregator, participant or target); the setup protocols pass through.
func (rt *Runtime) protocolGatePolicy() gatePolicy[protocols.Event] {
	return gatePolicy[protocols.Event]{
		key: func(ev protocols.Event) string { return ev.Signature.String() },
		gated: func(ev protocols.Event) bool {
			if !ev.Signature.Type.IsCompute() {
				return false
			}
			return ev.Aggregator == rt.self || slices.Contains(ev.Participants, rt.self) || ev.Args["target"] == string(rt.self)
		},
		terminal: func(ev protocols.Event) bool {
			return ev.EventType == protocols.Completed || ev.EventType == protocols.Failed
		},
		skippable: func(ev protocols.Event) bool { return ev.EventType == protocols.Executing },
		logf:      rt.Logf,
	}
}

// circuitGatePolicy gates the circuits in which the node has a role (evaluator or participant).
func (rt *Runtime) circuitGatePolicy() gatePolicy[circuits.Event] {
	roles := make(map[helium.CircuitID]bool) // accessed by the gate goroutine only
	return gatePolicy[circuits.Event]{
		key: func(ev circuits.Event) string { return string(ev.CircuitID) },
		gated: func(ev circuits.Event) bool {
			if hasRole, cached := roles[ev.CircuitID]; cached {
				return hasRole
			}
			md, err := rt.circuits.Metadata(ev.Descriptor)
			hasRole := err == nil && (md.IsEvaluator(rt.self) || md.IsParticipant(rt.self))
			roles[ev.CircuitID] = hasRole
			return hasRole
		},
		terminal: func(ev circuits.Event) bool {
			return ev.EventType == circuits.Completed || ev.EventType == circuits.Failed
		},
		skippable: func(ev circuits.Event) bool { return ev.EventType == circuits.Executing },
		logf:      rt.Logf,
	}
}
