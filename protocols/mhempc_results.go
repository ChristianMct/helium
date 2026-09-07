package protocols

import (
	"context"
	"errors"
	"fmt"
)

// GetAggregationOutput returns the aggregated share of the protocol described by pd.
// The share is looked up in the local result backend first. If not available and
// this node aggregates pd, the method waits for the running protocol to complete.
// Otherwise, the share is queried from the protocol's aggregator through the
// transport and stored locally.
func (e *MHEMPC) GetAggregationOutput(ctx context.Context, pd Descriptor) (*AggregationOutput, error) {
	share, err := e.results.Get(pd)
	if err == nil {
		return &AggregationOutput{Descriptor: pd, Share: share}, nil
	}
	if !errors.Is(err, ErrResultNotFound) {
		return nil, err
	}

	if e.isAggregator(pd) {
		e.mu.Lock()
		rp, running := e.running[pd.ID()]
		e.mu.Unlock()
		if !running {
			return nil, fmt.Errorf("no aggregation output for %s: protocol is neither running nor completed at this node", pd.HID())
		}
		select {
		case <-rp.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if share, err = e.results.Get(pd); err != nil {
			return nil, fmt.Errorf("protocol %s terminated without output: %w", pd.HID(), err)
		}
		return &AggregationOutput{Descriptor: pd, Share: share}, nil
	}

	share, err = e.trans.GetAggregationOutput(ctx, pd)
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
	if err := e.results.Put(pd, share); err != nil {
		e.Logf("could not store fetched aggregation output for %s: %s", pd.HID(), err)
	}
	return &AggregationOutput{Descriptor: pd, Share: share}, nil
}

// GetOutput returns the finalized output of the protocol described by pd (e.g., a
// public key or a key-switched ciphertext), computing it from the aggregated share
// (see GetAggregationOutput) and caching it.
func (e *MHEMPC) GetOutput(ctx context.Context, pd Descriptor) (*Output, error) {
	pid := pd.ID()
	e.mu.Lock()
	out, has := e.outputs[pid]
	e.mu.Unlock()
	if has {
		return &out, nil
	}

	switch pd.Signature.Type {
	case CKG, RTG, RKG, DEC:
	default:
		return nil, fmt.Errorf("protocol type %s has no output", pd.Signature.Type)
	}

	aggOut, err := e.GetAggregationOutput(ctx, pd)
	if err != nil {
		return nil, err
	}
	in, err := e.getInput(ctx, pd)
	if err != nil {
		return nil, fmt.Errorf("cannot get input for %s: %w", pd.HID(), err)
	}
	proto, err := NewProtocol(pd, e.sess)
	if err != nil {
		return nil, err
	}
	res := AllocateOutput(pd.Signature, *e.sess.Params.GetRLWEParameters())
	if allocErr, isErr := res.(error); isErr {
		return nil, allocErr
	}
	if err := proto.Output(in, *aggOut, res); err != nil {
		return nil, fmt.Errorf("cannot compute output for %s: %w", pd.HID(), err)
	}

	out = Output{Descriptor: pd, Result: res}
	e.mu.Lock()
	e.outputs[pid] = out
	e.mu.Unlock()
	return &out, nil
}

// AwaitCompleted blocks until a protocol with the given signature has completed,
// and returns its descriptor.
func (e *MHEMPC) AwaitCompleted(ctx context.Context, sig Signature) (Descriptor, error) {
	key := sig.String()
	e.mu.Lock()
	if pd, has := e.bySig[key]; has {
		e.mu.Unlock()
		return pd, nil
	}
	w := make(chan Descriptor, 1)
	e.waiters[key] = append(e.waiters[key], w)
	e.mu.Unlock()

	select {
	case pd := <-w:
		return pd, nil
	case <-ctx.Done():
		return Descriptor{}, ctx.Err()
	}
}

// CompletedDescriptor returns the descriptor of the last completed protocol with
// the given signature, if any.
func (e *MHEMPC) CompletedDescriptor(sig Signature) (Descriptor, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	pd, has := e.bySig[sig.String()]
	return pd, has
}

// IsRunning returns whether the protocol described by pd is running at this node.
func (e *MHEMPC) IsRunning(pd Descriptor) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, has := e.running[pd.ID()]
	return has
}

// IsCompleted returns whether the protocol described by pd is completed.
func (e *MHEMPC) IsCompleted(pd Descriptor) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, has := e.completed[pd.ID()]
	return has
}

// RestoreCompleted marks as completed the protocols with the given signatures for
// which the result backend holds a result (e.g., after a restart). For the RKG
// signature, the first round is restored as well. It returns the restored descriptors.
func (e *MHEMPC) RestoreCompleted(sigs ...Signature) ([]Descriptor, error) {
	var restored []Descriptor
	for _, sig := range sigs {
		toRestore := []Signature{sig}
		if sig.Type == RKG {
			toRestore = append([]Signature{{Type: RKG1, Args: sig.Args}}, sig)
		}
		for _, s := range toRestore {
			pd, has, err := e.results.CompletedDescriptor(s)
			if err != nil {
				return restored, fmt.Errorf("error while restoring %s: %w", s, err)
			}
			if !has {
				continue
			}
			e.mu.Lock()
			e.markCompleted(pd)
			e.mu.Unlock()
			restored = append(restored, pd)
		}
	}
	return restored, nil
}

// getInput returns the input of the protocol described by pd:
//   - the CRP for the key-generation protocols (derived from the session's public seed),
//   - the aggregated first-round share for RKG (fetched from the aggregator if needed),
//   - the key-switch input from the KeySwitchInputProvider for DEC, CKS and PCKS.
func (e *MHEMPC) getInput(ctx context.Context, pd Descriptor) (Input, error) {
	switch pd.Signature.Type {
	case CKG, RTG, RKG1:
		p, err := NewProtocol(pd, e.sess)
		if err != nil {
			return nil, err
		}
		return p.ReadCRP()
	case RKG:
		aggOutR1, err := e.GetAggregationOutput(ctx, rkg1Descriptor(pd))
		if err != nil {
			return nil, fmt.Errorf("cannot get first round output: %w", err)
		}
		return aggOutR1.Share.MHEShare, nil
	case DEC, CKS, PCKS:
		if e.ksInput == nil {
			return nil, fmt.Errorf("node has no key-switch input provider")
		}
		return e.ksInput(ctx, pd)
	default:
		return nil, fmt.Errorf("no input for protocol type %s", pd.Signature.Type)
	}
}

// rkg1Descriptor returns the descriptor of the first round of the RKG protocol described by pd.
func rkg1Descriptor(pd Descriptor) Descriptor {
	return Descriptor{
		Signature:    Signature{Type: RKG1, Args: pd.Signature.Args},
		Participants: pd.Participants,
		Aggregator:   pd.Aggregator,
	}
}
