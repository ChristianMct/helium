package protocols

import (
	"fmt"
	"slices"

	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

type keySwitchProtocol struct {
	patProtocol
	target    pkg.NodeID
	ks        MHEKeySwitchProtocol
	outputKey ReceiverKey
	input     *rlwe.Ciphertext
}

func NewKeyswitchProtocol(pd Descriptor, sess *pkg.Session, input ...Input) (Instance, error) {

	prot, err := newPATProtocol(pd, sess)
	if err != nil {
		return nil, err
	}

	ks := &keySwitchProtocol{
		patProtocol: *prot,
	}

	ks.ks = ks.proto.(MHEKeySwitchProtocol)

	if _, hasArg := pd.Signature.Args["target"]; !hasArg {
		return nil, fmt.Errorf("should provide argument: target")
	}

	ks.target = pkg.NodeID(pd.Signature.Args["target"])

	if len(input) == 0 {
		return nil, fmt.Errorf("no input specified")
	}

	var isCt bool
	if ks.input, isCt = input[0].(*rlwe.Ciphertext); !isCt {
		return nil, fmt.Errorf("keyswitch protocol require a *rlwe.Ciphertext as input parameter, got %T", input[0])
	}

	switch pd.Signature.Type {
	case CKS:
		return nil, fmt.Errorf("standalone CKS protocol not supported yet") // TODO
	case DEC:
		if sess.Contains(ks.target) && !slices.Contains(pd.Participants, ks.target) {
			return nil, fmt.Errorf("a session target must be a protocol participant in DEC")
		}
		if !sess.Contains(ks.target) && ks.pd.Aggregator != ks.target {
			return nil, fmt.Errorf("target for protocol DEC should be a session node or the aggreator, was %s", ks.target)
		}
		ks.outputKey = rlwe.NewSecretKey(sess.Params) // target key is zero for decryption // TODO caching of this value
	case PCKS:
		return nil, fmt.Errorf("PCKS not supported yet") // TODO
	}
	if err != nil {
		return nil, err
	}

	// TODO: below is same as keygen protocols

	if ks.IsAggregator() {
		ks.agg = newShareAggregator(pd, ks.AllocateShare(), ks.ks.AggregatedShares) // TODO: could cache the shares
	}
	return ks, nil
}

func (p *keySwitchProtocol) GenShare(sk *rlwe.SecretKey, share *Share) error {

	if !p.IsParticipant() {
		return fmt.Errorf("node is not a participant")
	}

	if p.pd.Type == DEC && p.target == p.self {
		return fmt.Errorf("node is decryption receiver")
	}

	if p.input == nil {
		return fmt.Errorf("no input provided to protocol")
	}

	share.ProtocolID = p.id
	share.From = utils.NewSingletonSet(p.self)
	share.ProtocolType = p.pd.Type
	return p.ks.GenShare(sk, p.outputKey, p.input, *share)
}

func (p *keySwitchProtocol) Output(agg AggregationOutput) chan Output {
	out := make(chan Output, 1)
	if agg.Error != nil {
		out <- Output{Error: fmt.Errorf("error at aggregation: %w", agg.Error)}
		return out
	}
	res := p.input.CopyNew()
	err := p.ks.Finalize(p.input, res, agg.Share)
	if err != nil {
		out <- Output{Error: fmt.Errorf("error at finalization: %w", err)}
		return out
	}
	p.Logf("finalized protocol")
	out <- Output{Result: res}
	return out
}
