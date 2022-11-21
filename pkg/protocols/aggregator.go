package protocols

import (
	"encoding"
	"fmt"
	"sync"

	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/ldsec/helium/pkg/utils"
)

type ShareInt interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

type AggregatedShareInt interface {
	Share() ShareInt
	AggregateFor() utils.Set[pkg.NodeID]
}

type AggregatedShare[S Share] struct {
	s            S
	aggregateFor utils.Set[pkg.NodeID]
}

func (s *AggregatedShare[S]) Share() ShareInt {
	return s.s
}

func (s *AggregatedShare[S]) AggregateFor() utils.Set[pkg.NodeID] {
	return s.aggregateFor
}

type ProtocolAggregator[S Share] interface {
	AggregateShares(S, S, S)
}

type AggregatorOf[S Share] struct {
	sync.RWMutex
	sync.Cond
	ProtocolAggregator[S]

	aggShare             S
	expected, aggregated utils.Set[pkg.NodeID]
}

func NewAggregatorOf[S Share](expected utils.Set[pkg.NodeID], buff S, aggObj ProtocolAggregator[S]) *AggregatorOf[S] {
	agg := new(AggregatorOf[S])
	agg.Cond = *sync.NewCond(&agg.RWMutex)
	agg.expected, agg.aggregated = expected.Copy(), utils.NewEmptySet[pkg.NodeID]()
	agg.aggShare = buff
	agg.ProtocolAggregator = aggObj
	return agg
}

func (a *AggregatorOf[S]) PutShare(share *AggregatedShare[S]) (bool, error) {
	if len(share.aggregateFor) == 0 {
		return false, fmt.Errorf("aggFor should not be empty")
	}
	if !a.expected.Includes(share.aggregateFor) {
		return false, fmt.Errorf("unexpected share in aggregate")
	}
	a.Lock()
	if !a.aggregated.Disjoint(share.aggregateFor) {
		return false, fmt.Errorf("non-disjoint aggregate")
	}
	a.AggregateShares(share.s, a.aggShare, a.aggShare)
	a.aggregated.AddAll(share.aggregateFor)
	complete := a.Complete()
	if complete {
		a.Broadcast()
	}
	a.Unlock()
	return complete, nil
}

func (a *AggregatorOf[S]) GetShare() *AggregatedShare[S] {
	a.Lock()
	for !a.Complete() {
		a.Wait()
	}
	a.Unlock()
	return &AggregatedShare[S]{s: a.aggShare, aggregateFor: a.aggregated}
}

func (a *AggregatorOf[S]) Complete() bool {
	return a.expected.Equals(a.aggregated)
}
