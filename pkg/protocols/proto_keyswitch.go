package protocols

import (
	"context"
	"fmt"
	"log"

	"github.com/ldsec/helium/pkg"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

type keySwitchProtocol struct {
	*protocol
	proto     LattigoKeySwitchProtocol
	target    pkg.NodeID
	outputKey OutputKey
	agg       shareAggregator
	inputChan chan *rlwe.Ciphertext
	input     *rlwe.Ciphertext
}

func NewKeyswitchProtocol(params rlwe.Parameters, pd Descriptor, sk *rlwe.SecretKey, outputKey OutputKey, pid pkg.ProtocolID, nid pkg.NodeID) (KeySwitchInstance, error) {

	if _, hasArg := pd.Args["target"]; !hasArg {
		return nil, fmt.Errorf("should provide argument: target")
	}
	target, isString := pd.Args["target"]
	if !isString {
		return nil, fmt.Errorf("invalid target type %T instead of %T", pd.Args["target"], target)
	}

	ks := new(keySwitchProtocol)
	ks.target = pkg.NodeID(target)
	ks.inputChan = make(chan *rlwe.Ciphertext, 1)

	ks.protocol = newProtocol(params, pd, sk, pid, nid)
	var err error
	switch pd.Type {
	case CKS:
		return nil, fmt.Errorf("generic standalone CKS protocol not supported yet") // TODO
	case DEC:
		ks.proto, err = NewCKSProtocol(params, pd.Args)
		ks.outputKey = rlwe.NewSecretKey(params) // target key is zero for decryption
	case PCKS:
		ks.proto, err = NewPCKSProtocol(params, pd.Args)
		ks.outputKey = outputKey
	}
	if err != nil {
		ks = nil
	}
	return ks, nil
}

func (p *keySwitchProtocol) Aggregate(ctx context.Context, env Transport) chan AggregationOutput {
	agg := make(chan AggregationOutput, 1)
	go func() {
		agg <- p.aggregate(ctx, env)
	}()
	return agg
}

func (p *keySwitchProtocol) aggregate(ctx context.Context, env Transport) AggregationOutput {
	log.Printf("%s | [%s] started running with %v\n", p.self, p.ID(), p.Descriptor)

	// part := utils.NewSet(p.Descriptor.Participants) // TODO: reads from protomap for now
	// if p.Descriptor.Type == CKS || p.Descriptor.Type == DEC {
	// 	part.Remove(p.target)
	// }

	p.input = <-p.inputChan

	var share Share
	if p.IsAggregator() || p.shareProviders.Contains(p.self) {
		share = p.proto.AllocateShare()
		share.ProtocolID = p.ID()
		share.Type = p.Type
		share.From = p.self
		share.AggregateFor = utils.NewEmptySet[pkg.NodeID]()
		share.Round = 1
	}

	if p.shareProviders.Contains(p.self) {
		skGroup := p.shareProviders.Copy()
		if p.Type == DEC {
			skGroup.Add(p.target)
		}
		errGen := p.proto.GenShare(p.sk, p.outputKey, p.input, share)
		if errGen != nil {
			panic(errGen)
		}
		share.To = []pkg.NodeID{p.Desc().Aggregator}
		share.AggregateFor.Add(p.self)
	}

	if p.IsAggregator() {
		p.agg = *newShareAggregator(p.shareProviders, share, p.proto.AggregatedShares)

		errAggr := p.aggregateShares(ctx, p.agg, env)
		if errAggr != nil {
			log.Printf("%s | [%s] failed: %s\n", p.self, p.ID(), errAggr)
			return AggregationOutput{Error: errAggr}
		}
		share.AggregateFor = p.shareProviders.Copy()
		return AggregationOutput{Round: []Share{share}}
	}
	if p.shareProviders.Contains(p.self) {
		env.OutgoingShares() <- share
	}
	log.Printf("%s | [%s] completed aggregation\n", p.self, p.ID())
	return AggregationOutput{}
}

func (p *keySwitchProtocol) Input(ct *rlwe.Ciphertext) {
	p.inputChan <- ct
}

func (p *keySwitchProtocol) Output(agg AggregationOutput) chan Output {
	out := make(chan Output, 1)
	if agg.Error != nil {
		out <- Output{Error: fmt.Errorf("error at aggregation: %w", agg.Error)}
		return out
	}
	res := p.input.CopyNew()
	err := p.proto.Finalize(p.input, res, agg.Round[0])
	if err != nil {
		out <- Output{Error: fmt.Errorf("error at finalization: %w", err)}
		return out
	}
	log.Printf("%s | [%s] finalized protocol\n", p.self, p.ID())
	out <- Output{Result: res}
	return out
}
