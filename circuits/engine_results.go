package circuits

import (
	"context"
	"fmt"

	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/sessions"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
)

// GetOperand returns the operand with the given id. The operand is looked up in the
// local store first. If this node is evaluating the circuit the operand belongs to,
// the method waits for the operand to be available. Otherwise, the operand is queried
// from its owner through the transport and stored locally.
func (e *Engine) GetOperand(ctx context.Context, id OperandID) (*Operand, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}

	e.mu.Lock()
	op, has := e.operands[id]
	rc, running := e.running[id.CircuitID()]
	e.mu.Unlock()
	if has {
		return op, nil
	}

	if running && e.isEvaluator(rc.md) {
		if fop, isInput := rc.inputs[id]; isInput {
			select {
			case <-fop.Done():
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			in := fop.Get()
			return &in, nil
		}
		if _, isOutput := rc.md.Outputs[id.Name()]; isOutput && id.NodeID() == e.self {
			select {
			case <-rc.done:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			e.mu.Lock()
			op, has = e.operands[id]
			e.mu.Unlock()
			if !has {
				return nil, fmt.Errorf("circuit %s terminated without output %s", rc.cd.HID(), id.Name())
			}
			return op, nil
		}
	}

	if id.NodeID() == e.self {
		return nil, fmt.Errorf("operand %s not found", id)
	}

	op, err := e.trans.GetOperand(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("error when querying transport for operand %s: %w", id, err)
	}
	if op == nil || op.Ciphertext == nil {
		return nil, fmt.Errorf("transport returned an empty operand for %s", id)
	}
	op.ID = id
	e.mu.Lock()
	e.operands[id] = op
	e.mu.Unlock()
	return op, nil
}

// AwaitCompleted blocks until the circuit with the given id has terminated. It returns
// the circuit's descriptor if it completed, and an error if it failed.
func (e *Engine) AwaitCompleted(ctx context.Context, cid sessions.CircuitID) (Descriptor, error) {
	e.mu.Lock()
	if cd, has := e.completed[cid]; has {
		e.mu.Unlock()
		return cd, nil
	}
	if cd, has := e.failed[cid]; has {
		e.mu.Unlock()
		return Descriptor{}, fmt.Errorf("circuit %s failed", cd.HID())
	}
	w := make(chan completion, 1)
	e.waiters[cid] = append(e.waiters[cid], w)
	e.mu.Unlock()

	select {
	case c := <-w:
		return c.cd, c.err
	case <-ctx.Done():
		return Descriptor{}, ctx.Err()
	}
}

// AwaitIdle blocks until no circuit is running at this node and all the engine's
// events have been published.
func (e *Engine) AwaitIdle(ctx context.Context) error {
	e.mu.Lock()
	if e.idle() {
		e.mu.Unlock()
		return nil
	}
	w := make(chan struct{})
	e.idleWaiters = append(e.idleWaiters, w)
	e.mu.Unlock()

	select {
	case <-w:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// IsRunning returns whether the circuit with the given id is running at this node.
func (e *Engine) IsRunning(cid sessions.CircuitID) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, has := e.running[cid]
	return has
}

// IsCompleted returns whether the circuit with the given id is completed.
func (e *Engine) IsCompleted(cid sessions.CircuitID) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, has := e.completed[cid]
	return has
}

// CompletedDescriptor returns the descriptor of the completed circuit with the given id, if any.
func (e *Engine) CompletedDescriptor(cid sessions.CircuitID) (Descriptor, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	cd, has := e.completed[cid]
	return cd, has
}

// GetKeySwitchInput returns the input of a key-switching protocol whose "op" argument
// is an operand id, by retrieving the operand (see GetOperand). It is meant to be used
// as the protocols.KeySwitchInputProvider of the node's protocol engine.
func (e *Engine) GetKeySwitchInput(ctx context.Context, pd protocols.Descriptor) (*protocols.KeySwitchInput, error) {
	opID, has := pd.Signature.Args["op"]
	if !has {
		return nil, fmt.Errorf("invalid protocol descriptor: no operand specified")
	}

	op, err := e.GetOperand(ctx, OperandID(opID))
	if err != nil {
		return nil, err
	}

	ksin := &protocols.KeySwitchInput{InpuCt: op.Ciphertext}
	switch pd.Signature.Type {
	case protocols.DEC:
		ksin.OutputKey = rlwe.NewSecretKey(e.sess.Params)
	case protocols.CKS, protocols.PCKS:
		return nil, fmt.Errorf("key switch protocol not supported yet") // TODO
	default:
		return nil, fmt.Errorf("invalid protocol type: %s", pd.Signature.Type)
	}
	return ksin, nil
}
