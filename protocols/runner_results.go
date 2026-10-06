package protocols

import (
	"context"
	"errors"
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// GetAggregationOutput returns the aggregated share of the protocol described by pd.
// The share is looked up in the local result backend first. If not available and
// this node aggregates pd, the method waits for the running protocol to complete.
// Otherwise, the share is queried from the protocol's aggregator through the
// transport and stored locally.
func (r *Runner) GetAggregationOutput(ctx context.Context, pd Descriptor) (*AggregationOutput, error) {
	share, err := r.results.Get(pd)
	if err == nil {
		return &AggregationOutput{Descriptor: pd, Share: share}, nil
	}
	if !errors.Is(err, ErrResultNotFound) {
		return nil, err
	}

	if r.isAggregator(pd) {
		r.mu.Lock()
		rp, running := r.running[pd.ID()]
		r.mu.Unlock()
		if !running {
			return nil, fmt.Errorf("no aggregation output for %s: protocol is neither running nor completed at this node", pd.HID())
		}
		select {
		case <-rp.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if share, err = r.results.Get(pd); err != nil {
			return nil, fmt.Errorf("protocol %s terminated without output: %w", pd.HID(), err)
		}
		return &AggregationOutput{Descriptor: pd, Share: share}, nil
	}

	share, err = r.trans.GetAggregationOutput(ctx, pd)
	if err != nil {
		return nil, fmt.Errorf("error when querying transport for aggregation output of %s: %w", pd.HID(), err)
	}
	if share.MHEShare == nil {
		return nil, fmt.Errorf("transport returned a nil share for %s", pd.HID())
	}
	share.ProtocolID = pd.ID()
	share.ProtocolType = pd.Signature.Type
	if len(share.From) == 0 {
		share.From = shareProviders(pd)
	}
	if err := r.results.Put(pd, share); err != nil {
		r.Logf("could not store fetched aggregation output for %s: %s", pd.HID(), err)
	}
	return &AggregationOutput{Descriptor: pd, Share: share}, nil
}

// GetOutput returns the finalized output of the protocol described by pd (e.g., a
// public key or a key-switched ciphertext), computing it from the aggregated share
// (see GetAggregationOutput) and caching it.
func (r *Runner) GetOutput(ctx context.Context, pd Descriptor) (*Output, error) {
	pid := pd.ID()
	r.mu.Lock()
	out, has := r.outputs[pid]
	r.mu.Unlock()
	if has {
		return &out, nil
	}

	switch pd.Signature.Type {
	case CKG, RTG, RKG, DEC:
	default:
		return nil, fmt.Errorf("protocol type %s has no output", pd.Signature.Type)
	}

	aggOut, err := r.GetAggregationOutput(ctx, pd)
	if err != nil {
		return nil, err
	}
	in, err := r.getInput(ctx, pd)
	if err != nil {
		return nil, fmt.Errorf("cannot get input for %s: %w", pd.HID(), err)
	}
	proto, err := NewProtocol(pd, r.sess)
	if err != nil {
		return nil, err
	}
	res := AllocateOutput(pd.Signature, *r.sess.Params.GetRLWEParameters())
	if allocErr, isErr := res.(error); isErr {
		return nil, allocErr
	}
	if err := proto.Output(in, *aggOut, res); err != nil {
		return nil, fmt.Errorf("cannot compute output for %s: %w", pd.HID(), err)
	}

	out = Output{Descriptor: pd, Result: res}
	r.mu.Lock()
	r.outputs[pid] = out
	r.mu.Unlock()
	return &out, nil
}

// AwaitCompleted blocks until a protocol with the given signature has completed,
// and returns its descriptor.
func (r *Runner) AwaitCompleted(ctx context.Context, sig Signature) (Descriptor, error) {
	key := sig.String()
	r.mu.Lock()
	if pd, has := r.bySig[key]; has {
		r.mu.Unlock()
		return pd, nil
	}
	w := make(chan Descriptor, 1)
	r.waiters[key] = append(r.waiters[key], w)
	r.mu.Unlock()

	select {
	case pd := <-w:
		return pd, nil
	case <-ctx.Done():
		return Descriptor{}, ctx.Err()
	}
}

// CompletedDescriptor returns the descriptor of the last completed protocol with
// the given signature, if any.
func (r *Runner) CompletedDescriptor(sig Signature) (Descriptor, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pd, has := r.bySig[sig.String()]
	return pd, has
}

// IsRunning returns whether the protocol described by pd is running at this node.
func (r *Runner) IsRunning(pd Descriptor) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, has := r.running[pd.ID()]
	return has
}

// IsCompleted returns whether the protocol described by pd is completed.
func (r *Runner) IsCompleted(pd Descriptor) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, has := r.completed[pd.ID()]
	return has
}

// RestoreCompleted marks as completed the protocols with the given signatures for
// which the result backend holds a result (e.g., after a restart). For the RKG
// signature, the first round is restored as well. It returns the restored descriptors.
func (r *Runner) RestoreCompleted(sigs ...Signature) ([]Descriptor, error) {
	var restored []Descriptor
	for _, sig := range sigs {
		toRestore := []Signature{sig}
		if sig.Type == RKG {
			toRestore = append([]Signature{{Type: RKG1, Args: sig.Args}}, sig)
		}
		for _, s := range toRestore {
			pd, has, err := r.results.CompletedDescriptor(s)
			if err != nil {
				return restored, fmt.Errorf("error while restoring %s: %w", s, err)
			}
			if !has {
				continue
			}
			r.mu.Lock()
			r.markCompleted(pd)
			r.mu.Unlock()
			restored = append(restored, pd)
		}
	}
	return restored, nil
}

// getInput returns the input of the protocol described by pd:
//   - the CRP for the key-generation protocols (derived from the session's public seed),
//   - the aggregated first-round share for RKG (fetched from the aggregator if needed),
//   - the key-switch input from the KeySwitchInputProvider for DEC, CKS and PCKS.
func (r *Runner) getInput(ctx context.Context, pd Descriptor) (Input, error) {
	switch pd.Signature.Type {
	case CKG, RTG, RKG1:
		p, err := NewProtocol(pd, r.sess)
		if err != nil {
			return nil, err
		}
		return p.ReadCRP()
	case RKG:
		aggOutR1, err := r.GetAggregationOutput(ctx, rkg1Descriptor(pd))
		if err != nil {
			return nil, fmt.Errorf("cannot get first round output: %w", err)
		}
		return aggOutR1.Share.MHEShare, nil
	case DEC, CKS, PCKS:
		if r.ksInput == nil {
			return nil, fmt.Errorf("node has no key-switch input provider")
		}
		return r.ksInput(ctx, pd)
	default:
		return nil, fmt.Errorf("no input for protocol type %s", pd.Signature.Type)
	}
}

// DecryptOutput returns the plaintext output of the decryption protocol described by pd,
// as seen by its target. The method retrieves the protocol output (see GetOutput), which
// is encrypted under the target's share of the group secret key, and decrypts it. A target
// that has no secret in the session (e.g., the helper node) obtains the plaintext directly.
func (r *Runner) DecryptOutput(ctx context.Context, pd Descriptor) (*rlwe.Plaintext, error) {
	if pd.Signature.Type != DEC {
		return nil, fmt.Errorf("protocol %s is not a decryption protocol", pd.HID())
	}
	if !r.isKeySwitchReceiver(pd) {
		return nil, fmt.Errorf("node %s is not the target of %s", r.self, pd.HID())
	}

	out, err := r.GetOutput(ctx, pd)
	if err != nil {
		return nil, err
	}
	ct, isCt := out.Result.(*rlwe.Ciphertext)
	if !isCt {
		return nil, fmt.Errorf("output of %s is not a ciphertext: %T", pd.HID(), out.Result)
	}

	pt := rlwe.NewPlaintext(r.sess.Params, ct.Level())
	if !r.sess.Contains(r.self) {
		// the target has no secret key: the output is encrypted under the zero key
		pt.Value.Copy(ct.Value[0])
		*pt.MetaData = *ct.MetaData
		return pt, nil
	}

	sk, err := r.sess.GetSecretKeyForGroup(pd.Participants)
	if err != nil {
		return nil, fmt.Errorf("cannot get group secret key: %w", err)
	}
	rlwe.NewDecryptor(r.sess.Params, sk).Decrypt(ct, pt)
	return pt, nil
}

// rkg1Descriptor returns the descriptor of the first round of the RKG protocol described by pd.
func rkg1Descriptor(pd Descriptor) Descriptor {
	return Descriptor{
		Signature:    Signature{Type: RKG1, Args: pd.Signature.Args},
		Participants: pd.Participants,
		Aggregator:   pd.Aggregator,
	}
}
