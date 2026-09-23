package circuits

import (
	"context"
	"fmt"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/protocols"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// GetOperand returns the operand with the given id. The operand is looked up in the
// local store first. If this node is evaluating the circuit the operand belongs to,
// the method waits for the operand to be available. Otherwise, the operand is queried
// from its owner through the transport and stored locally.
func (r *Runner) GetOperand(ctx context.Context, id helium.OperandID) (*helium.Operand, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}

	r.mu.Lock()
	op, has := r.operands[id]
	rc, running := r.running[id.CircuitID()]
	r.mu.Unlock()
	if has {
		return op, nil
	}

	if running && r.isEvaluator(rc.md) {
		if fop, isInput := rc.inputs[id]; isInput {
			select {
			case <-fop.Done():
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			in := fop.Get()
			return &in, nil
		}
		if _, isOutput := rc.md.Outputs[id.Name()]; isOutput && id.NodeID() == r.self {
			select {
			case <-rc.done:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			r.mu.Lock()
			op, has = r.operands[id]
			r.mu.Unlock()
			if !has {
				return nil, fmt.Errorf("circuit %s terminated without output %s", rc.cd.HID(), id.Name())
			}
			return op, nil
		}
	}

	if id.NodeID() == r.self {
		return nil, fmt.Errorf("operand %s not found", id)
	}

	op, err := r.trans.GetOperand(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("error when querying transport for operand %s: %w", id, err)
	}
	if op == nil || op.Ciphertext == nil {
		return nil, fmt.Errorf("transport returned an empty operand for %s", id)
	}
	op.ID = id
	r.mu.Lock()
	r.operands[id] = op
	r.mu.Unlock()
	return op, nil
}

// AwaitCompleted blocks until the circuit with the given id has terminated. It returns
// the circuit's descriptor if it completed, and an error if it failed.
func (r *Runner) AwaitCompleted(ctx context.Context, cid helium.CircuitID) (helium.Descriptor, error) {
	r.mu.Lock()
	if cd, has := r.completed[cid]; has {
		r.mu.Unlock()
		return cd, nil
	}
	if cd, has := r.failed[cid]; has {
		r.mu.Unlock()
		return helium.Descriptor{}, fmt.Errorf("circuit %s failed", cd.HID())
	}
	w := make(chan completion, 1)
	r.waiters[cid] = append(r.waiters[cid], w)
	r.mu.Unlock()

	select {
	case c := <-w:
		return c.cd, c.err
	case <-ctx.Done():
		return helium.Descriptor{}, ctx.Err()
	}
}

// AwaitIdle blocks until no circuit is running at this node and all the runner's
// events have been published.
func (r *Runner) AwaitIdle(ctx context.Context) error {
	r.mu.Lock()
	if r.idle() {
		r.mu.Unlock()
		return nil
	}
	w := make(chan struct{})
	r.idleWaiters = append(r.idleWaiters, w)
	r.mu.Unlock()

	select {
	case <-w:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// IsRunning returns whether the circuit with the given id is running at this node.
func (r *Runner) IsRunning(cid helium.CircuitID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, has := r.running[cid]
	return has
}

// IsCompleted returns whether the circuit with the given id is completed.
func (r *Runner) IsCompleted(cid helium.CircuitID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, has := r.completed[cid]
	return has
}

// CompletedDescriptor returns the descriptor of the completed circuit with the given id, if any.
func (r *Runner) CompletedDescriptor(cid helium.CircuitID) (helium.Descriptor, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cd, has := r.completed[cid]
	return cd, has
}

// GetKeySwitchInput returns the input of a key-switching protocol whose "op" argument
// is an operand id, by retrieving the operand (see GetOperand). It is meant to be used
// as the protocols.KeySwitchInputProvider of the node's protocol runner.
func (r *Runner) GetKeySwitchInput(ctx context.Context, pd protocols.Descriptor) (*protocols.KeySwitchInput, error) {
	opID, has := pd.Signature.Args["op"]
	if !has {
		return nil, fmt.Errorf("invalid protocol descriptor: no operand specified")
	}

	op, err := r.GetOperand(ctx, helium.OperandID(opID))
	if err != nil {
		return nil, err
	}

	ksin := &protocols.KeySwitchInput{InpuCt: op.Ciphertext}
	switch pd.Signature.Type {
	case protocols.DEC:
		ksin.OutputKey = rlwe.NewSecretKey(r.sess.Params)
	case protocols.CKS, protocols.PCKS:
		return nil, fmt.Errorf("key switch protocol not supported yet") // TODO
	default:
		return nil, fmt.Errorf("invalid protocol type: %s", pd.Signature.Type)
	}
	return ksin, nil
}
