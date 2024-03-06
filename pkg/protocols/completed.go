package protocols

import (
	"fmt"
	"sync"
)

type CompleteMap struct {
	wg              sync.WaitGroup
	completedProtMu sync.RWMutex
	completedProt   map[string]chan Descriptor
	allowUnexpected bool
}

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

func (p *CompleteMap) Wait() error {
	p.wg.Wait()
	return nil // TODO error here ?
}
