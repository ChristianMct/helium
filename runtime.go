package helium

import (
	"context"
	"fmt"
	"log"
	"slices"
	"strconv"
	"sync"

	"github.com/ChristianMct/helium/circuits"
	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/sessions"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
)

// Runtime is the interface of the framework available to the application's Main
// function. It lets the application evaluate circuits and run decryption protocols;
// its methods block until the corresponding circuit or protocol has terminated.
//
// All the nodes run the same Main function, and a node takes part in a circuit or a
// protocol only once its Main has requested it: the coordination events of a circuit
// or protocol in which the node has a role are held until the matching Runtime call
// (see gate). On the helper node, the calls also start the circuits and protocols.
type Runtime struct {
	self sessions.NodeID
	sess *sessions.Session

	protocols *protocols.MHEMPC
	circuits  *circuits.Engine
	protoGate *gate[protocols.Event]
	circGate  *gate[circuits.Event]
	starter   starter // nil if the node is not the coordinator

	mu     sync.Mutex
	inputs map[sessions.CircuitID]map[string]any
}

// starter is implemented by the coordinating node to start circuits and protocols.
type starter interface {
	startCircuit(ctx context.Context, cd circuits.Descriptor) error
	startProtocol(ctx context.Context, sig protocols.Signature) error
}

func newRuntime(self sessions.NodeID, sess *sessions.Session, pe *protocols.MHEMPC, ce *circuits.Engine, st starter) *Runtime {
	rt := &Runtime{
		self:      self,
		sess:      sess,
		protocols: pe,
		circuits:  ce,
		starter:   st,
		inputs:    make(map[sessions.CircuitID]map[string]any),
	}
	rt.protoGate = newGate(rt.protocolGatePolicy())
	rt.circGate = newGate(rt.circuitGatePolicy())
	ce.SetInputProvider(rt.provideInputs)
	return rt
}

// Operand is a handle on a system-wide operand (an input or output of a circuit).
// Its ciphertext is fetched lazily from its owner.
type Operand struct {
	ID circuits.OperandID
	rt *Runtime
}

// Get returns the ciphertext of the operand, fetching it from its owner if necessary.
func (op Operand) Get(ctx context.Context) (*rlwe.Ciphertext, error) {
	if op.rt == nil {
		return nil, fmt.Errorf("operand %s is not bound to a runtime", op.ID)
	}
	o, err := op.rt.circuits.GetOperand(ctx, op.ID)
	if err != nil {
		return nil, err
	}
	return o.Ciphertext, nil
}

// ID returns the id of the node running the application.
func (rt *Runtime) ID() sessions.NodeID {
	return rt.self
}

// Session returns the session of the node.
func (rt *Runtime) Session() *sessions.Session {
	return rt.sess
}

// Parameters returns the FHE parameters of the session.
func (rt *Runtime) Parameters() sessions.FHEParameters {
	return rt.sess.Params
}

// IsCoordinator returns whether the node coordinates the circuits and protocols (the helper).
func (rt *Runtime) IsCoordinator() bool {
	return rt.starter != nil
}

// Operand returns a handle on the operand with the given id.
func (rt *Runtime) Operand(id circuits.OperandID) Operand {
	return Operand{ID: id, rt: rt}
}

// Evaluate evaluates the circuit described by cd and returns handles on its outputs, by
// name. The inputs are the node's inputs to the circuit, by input name (the name part of
// the node's input ports, or the name of a summed input): plaintext values ([]uint64,
// []int64 for BGV, []float64, []complex128 for CKKS), *rlwe.Plaintext, *rlwe.Ciphertext
// or Operand. The method blocks until the circuit has terminated at this node. On the
// coordinator, it also starts the circuit.
func (rt *Runtime) Evaluate(ctx context.Context, cd circuits.Descriptor, inputs map[string]any) (map[string]Operand, error) {
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
		if err := rt.starter.startCircuit(ctx, cd); err != nil {
			return nil, err
		}
	}

	if _, err := rt.circuits.AwaitCompleted(ctx, cd.CircuitID); err != nil {
		return nil, err
	}

	outs := make(map[string]Operand, len(md.Outputs))
	for name, id := range md.Outputs {
		outs[name] = Operand{ID: id, rt: rt}
	}
	return outs, nil
}

// Decrypt runs the decryption protocol of operand op towards the target node, with the
// given smudging noise (in bits). It blocks until the protocol has completed, and returns
// the plaintext on the target node (nil elsewhere). On the coordinator, it also starts
// the protocol.
func (rt *Runtime) Decrypt(ctx context.Context, op Operand, target sessions.NodeID, smudging float64) (*rlwe.Plaintext, error) {
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
		if err := rt.starter.startProtocol(ctx, sig); err != nil {
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

// finish signals the gates that the application is done.
func (rt *Runtime) finish() {
	rt.protoGate.finish()
	rt.circGate.finish()
}

// Logf logs a message with the node's prefix.
func (rt *Runtime) Logf(msg string, v ...any) {
	log.Printf("%s | [App] %s\n", rt.self, fmt.Sprintf(msg, v...))
}

// provideInputs is the circuits.InputProvider of the node's engine: it provides the inputs
// given to Evaluate.
func (rt *Runtime) provideInputs(ctx context.Context, cd circuits.Descriptor, ids []circuits.OperandID) (<-chan circuits.Input, error) {
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
		if op, isOp := v.(Operand); isOp {
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
	roles := make(map[sessions.CircuitID]bool) // accessed by the gate goroutine only
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
