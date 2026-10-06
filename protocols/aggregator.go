package protocols

import (
	"fmt"
	"sync"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/utils"
)

type shareAggregator struct {
	aggFunc func(Share, ...Share) error
	share   Share
	exp     utils.Set[helium.NodeID]
	l       sync.RWMutex
}

func newShareAggregator(pd Descriptor, share Share, aggFunc func(Share, ...Share) error) *shareAggregator {
	agg := new(shareAggregator)
	agg.exp = utils.NewSet(pd.Participants)
	if pd.Signature.Type == DEC { // the receiver does not provide a share in the DEC protocol
		agg.exp.Remove(helium.NodeID(pd.Signature.Args["target"]))
	}
	agg.share = share
	agg.aggFunc = aggFunc
	return agg
}

func (a *shareAggregator) put(share Share) (bool, error) {
	if len(share.From) == 0 {
		return false, fmt.Errorf("the From field should not be empty")
	}
	if !a.exp.Includes(share.From) {
		return false, fmt.Errorf("unexpected share in aggregate")
	}
	if !a.share.From.Disjoint(share.From) {
		//return false, fmt.Errorf("non-disjoint aggregate") // TODO: error matching for non-panic on this one
		return a.complete(), nil
	}
	a.l.Lock()
	defer a.l.Unlock()
	err := a.aggFunc(a.share, share)
	if err != nil {
		return a.complete(), err
	}
	a.share.From.AddAll(share.From)
	return a.complete(), nil
}

func (a *shareAggregator) missing() utils.Set[helium.NodeID] {
	a.l.RLock()
	defer a.l.RUnlock()
	return a.exp.Diff(a.share.From)
}

func (a *shareAggregator) getAggregatedShare() Share {
	a.l.RLock()
	defer a.l.RUnlock()
	if !a.complete() {
		return a.share.Copy()
	}
	return a.share
}

func (a *shareAggregator) complete() bool {
	return a.exp.Equals(a.share.From)
}
