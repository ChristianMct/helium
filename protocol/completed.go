package protocol

import (
	"fmt"
	"sync"
)

// CompleteMap implements a concurrent map of completed protocols.
// It enables waiting for the completion of a protocol and
// retrieving the completed descriptor.
type CompleteMap struct {
	wg              sync.WaitGroup
	completedProtMu sync.RWMutex
	completedProt   map[string]chan Descriptor
	allowUnexpected bool
}

// NewCompletedProt creates a new CompleteMap.
// If sigs is empty, the CompleteMap will allow callers of the
// AwaitCompletedDescriptorFor method to wait for any protocol
// descriptor completion. Otherwise, awaiting on an unknown
// protocol signature will return an error.
func NewCompletedProt(sigs []Signature) *CompleteMap {
	cp := new(CompleteMap)
	cp.completedProt = make(map[string]chan Descriptor)
	for _, sig := range sigs {
		cp.completedProt[sig.String()] = make(chan Descriptor, 1)
	}
	cp.wg.Add(len(sigs))
	cp.allowUnexpected = len(sigs) == 0
	return cp
}

// CompletedProtocol adds a completed protocol descriptor to the map.
func (p *CompleteMap) CompletedProtocol(pd Descriptor) error {
	p.completedProtMu.Lock()
	pdc, expected := p.completedProt[pd.Signature.String()]
	if !expected {
		if p.allowUnexpected {
			pdc = make(chan Descriptor, 1)
			p.completedProt[pd.Signature.String()] = pdc
			p.wg.Add(1)
		} else {
			return fmt.Errorf("unexpected completed descriptor for signature: %s", pd.Signature)
		}
	}
	p.completedProtMu.Unlock()
	pdc <- pd // TODO: will block if protocol completed two times
	p.wg.Done()
	return nil
}

// AwaitCompletedDescriptorFor waits for the completion of a protocol.
// This method will return an error if the map was created with a specific
// list of signatures and the provided signature is not in the list.
func (p *CompleteMap) AwaitCompletedDescriptorFor(sig Signature) (pdp *Descriptor, err error) {
	p.completedProtMu.Lock()
	incDesc, has := p.completedProt[sig.String()]
	if !has {
		if p.allowUnexpected {
			incDesc = make(chan Descriptor, 1)
			p.completedProt[sig.String()] = incDesc
			p.wg.Add(1)
		} else {
			return nil, fmt.Errorf("not waiting for completed protocol for sig %s", sig)
		}

	}
	p.completedProtMu.Unlock()
	pd := <-incDesc
	incDesc <- pd // TODO: haha
	pdc := pd
	return &pdc, nil
}

// Wait waits for all protocols to complete.
func (p *CompleteMap) Wait() error {
	p.wg.Wait()
	return nil // TODO error here ?
}
