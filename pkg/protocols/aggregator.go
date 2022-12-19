package protocols

import (
	"fmt"

	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/ldsec/helium/pkg/utils"
)

type shareAggregator struct {
	aggFunc  func(Share, ...Share) error
	share    Share
	expected utils.Set[pkg.NodeID]
}

func newShareAggregator(expected utils.Set[pkg.NodeID], share Share, aggFunc func(Share, ...Share) error) *shareAggregator {
	agg := new(shareAggregator)
	agg.expected = expected.Copy()
	agg.share = share
	agg.aggFunc = aggFunc
	return agg
}

func (a *shareAggregator) PutShare(share Share) (bool, error) {
	if len(share.AggregateFor) == 0 {
		return false, fmt.Errorf("aggFor should not be empty")
	}
	if !a.expected.Includes(share.AggregateFor) {
		return false, fmt.Errorf("unexpected share in aggregate")
	}
	if !a.share.AggregateFor.Disjoint(share.AggregateFor) {
		return false, fmt.Errorf("non-disjoint aggregate")
	}
	err := a.aggFunc(a.share, share)
	if err != nil {
		return a.Complete(), err
	}
	a.share.AggregateFor.AddAll(share.AggregateFor)
	return a.Complete(), nil
}

func (a *shareAggregator) GetAggregatedShare() Share {
	if !a.Complete() {
		return a.share.Copy()
	}
	return a.share
}

func (a *shareAggregator) Complete() bool {
	return a.expected.Equals(a.share.AggregateFor)
}
