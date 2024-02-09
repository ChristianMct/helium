package protocols

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/drlwe"
)

// pkProtocol is the protocol used to share public keys among parties.
type pkProtocol struct {
	*protocol
	proto LattigoKeygenProtocol
	agg   shareAggregator
	crs   drlwe.CRS
	crp   CRP
}

func (p *pkProtocol) Init(crp CRP) error {
	p.crp = crp
	return nil
}

func (p *pkProtocol) ReadCRP() (CRP, error) {
	return p.proto.ReadCRP(p.crs)
}

// // run runs the pkProtocol allowing participants to provide shares and aggregators to aggregate such shares.
// func (p *pkProtocol) run(ctx context.Context, env Transport) AggregationOutput {
// 	p.Logf("started running with participants %v", p.Descriptor.Participants)

// 	// pkProtocols can only have one participant: the sender of the public key
// 	if len(p.Participants) != 1 {
// 		panic(fmt.Errorf("error: a pkProtocol must have exactly one participant. p.Participants: %v", p.Participants))
// 	}

// 	if p.shareProviders.Contains(p.self) {

// 		if p.crp == nil {
// 			panic("Aggregate run before Init")
// 		}

// 		share := p.proto.AllocateShare()
// 		share.ProtocolID = p.ID()
// 		share.Type = p.Signature.Type
// 		share.To = []pkg.NodeID{p.Desc().Aggregator}
// 		share.From = p.self
// 		share.Round = 1

// 		errGen := p.proto.GenShare(p.sk, p.crp, share)
// 		if errGen != nil {
// 			panic(errGen)
// 		}

// 		env.OutgoingShares() <- share
// 		p.Logf("completed participating")
// 	}

// 	if p.IsAggregator() {
// 		select {
// 		case incShare := <-env.IncomingShares():
// 			p.Logf("new share from %s", incShare.From)
// 			p.Logf("completed aggregating")
// 			return AggregationOutput{Share: incShare}
// 			// share.
// 		case <-ctx.Done():
// 			return AggregationOutput{Error: fmt.Errorf("%s | timeout while aggregating shares for protocol %s, missing: %v", p.self, p.ID(), p.Participants)}
// 		}
// 	}

// 	p.Logf("completed running")
// 	return AggregationOutput{}
// }

// // Aggregate runs the protocol and returns a channel through which the output is send.
// func (p *pkProtocol) Aggregate(ctx context.Context, env Transport) chan AggregationOutput {
// 	output := make(chan AggregationOutput)
// 	go func() {
// 		output <- p.run(ctx, env)
// 	}()
// 	return output
// }

// Output takes an aggregation output and samples the CRP to reconstruct the Public Key.
func (p *pkProtocol) Output(agg AggregationOutput) chan Output {
	out := make(chan Output, 1)
	if agg.Error != nil {
		out <- Output{Error: fmt.Errorf("error at aggregation: %w", agg.Error)}
		return out
	}
	if p.crp == nil {
		var err error
		p.crp, err = p.proto.ReadCRP(p.crs)
		if err != nil {
			panic(err)
		}
	}
	res, err := p.proto.Finalize(p.crp, agg.Share)
	if err != nil {
		out <- Output{Error: fmt.Errorf("error at finalization: %w", err)}
		return out
	}
	p.Logf("finalized protocol")
	out <- Output{Result: res}
	return out
}
