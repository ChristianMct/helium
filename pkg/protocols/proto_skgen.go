package protocols

import (
	"context"
	"fmt"

	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v4/drlwe"
)

type skgProtocol struct {
	*protocol
	T     int
	spks  map[pkg.NodeID]drlwe.ShamirPublicPoint
	proto SKGProtocol
}

func (p *skgProtocol) Aggregate(ctx context.Context, env Transport) chan AggregationOutput {
	output := make(chan AggregationOutput)
	go func() {
		output <- p.aggregate(ctx, env)
	}()
	return output
}

func (p *skgProtocol) aggregate(ctx context.Context, env Transport) AggregationOutput {

	p.Logf("started running with participants %v", p.Descriptor.Participants)

	if !p.shareProviders.Contains(p.self) {
		p.Logf("finalized protocol (N=T)")
		return AggregationOutput{}
	}

	shamirPoly, err := p.proto.GenShamirPolynomial(p.T, p.sk)
	if err != nil {
		return AggregationOutput{Error: err}
	}

	ownShare := make(chan Share)
	for nodeID := range p.shareProviders { // TODO: parallel gen
		nodeID := nodeID
		go func() {

			share := p.proto.AllocateShare()
			errGen := p.proto.GenShareForParty(shamirPoly, p.spks[nodeID], share)
			if errGen != nil {
				panic(errGen)
			}
			share.ProtocolID = p.ID()
			share.Type = p.Signature.Type
			share.From = p.self
			share.To = []pkg.NodeID{nodeID}
			share.AggregateFor = utils.NewSingletonSet(p.self)
			share.Round = 1
			if nodeID == p.self {
				ownShare <- share
			} else {
				env.OutgoingShares() <- share
			}
		}()

	}

	agg := newShareAggregator(p.shareProviders, <-ownShare, p.proto.AggregatedShares)
	err = p.aggregateShares(ctx, *agg, env) // TODO pointer param
	if err != nil {
		p.Logf("failed: %s", err)
		return AggregationOutput{Error: err}
	}

	p.Logf("completed aggregation")

	p.Logf("finalized protocol")
	return AggregationOutput{Share: agg.GetAggregatedShare()}
}

func (p skgProtocol) Output(agg AggregationOutput) chan Output { // TODO Copy-past from pkProtocol
	out := make(chan Output, 1)
	if agg.Error != nil {
		out <- Output{Error: fmt.Errorf("error at aggregation: %w", agg.Error)}
		return out
	}
	p.Logf("finalized protocol")
	out <- Output{Result: agg.Share.MHEShare.(*drlwe.ShamirSecretShare)}
	return out
}
