package protocols

import (
	"fmt"
	"slices"

	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

type keySwitchProtocol struct {
	protocol
	target    pkg.NodeID
	proto     LattigoKeySwitchProtocol
	outputKey OutputKey
	input     *rlwe.Ciphertext
}

func NewKeyswitchProtocol(pd Descriptor, sess *pkg.Session, input ...Input) (Instance, error) {

	prot, err := newProtocol(pd, sess)
	if err != nil {
		return nil, err
	}

	ks := &keySwitchProtocol{
		protocol: *prot,
	}

	if _, hasArg := pd.Signature.Args["target"]; !hasArg {
		return nil, fmt.Errorf("should provide argument: target")
	}

	ks.target = pkg.NodeID(pd.Signature.Args["target"])

	if len(input) == 0 {
		return nil, fmt.Errorf("no input specified")
	}

	var isCt bool
	if ks.input, isCt = input[0].(*rlwe.Ciphertext); !isCt {
		return nil, fmt.Errorf("keyswitch protocol require a rlwe.Ciphertext as input parameter")
	}

	switch pd.Signature.Type {
	case CKS:
		return nil, fmt.Errorf("standalone CKS protocol not supported yet") // TODO
	case DEC:
		if sess.Contains(ks.target) && !slices.Contains(pd.Participants, ks.target) {
			return nil, fmt.Errorf("a session target must be a protocol participant in DEC")
		}
		if !sess.Contains(ks.target) && ks.Aggregator != ks.target {
			return nil, fmt.Errorf("target for protocol DEC should be a session node or the aggreator, was %s", ks.target)
		}
		ks.proto, err = NewCKSProtocol(sess.Params.Parameters, pd.Signature.Args)
		ks.outputKey = rlwe.NewSecretKey(sess.Params) // target key is zero for decryption // TODO caching of this value
	case PCKS:
		return nil, fmt.Errorf("PCKS not supported yet") // TODO
	}
	if err != nil {
		return nil, err
	}

	// TODO: below is same as keygen protocols
	ks.pubrand = GetProtocolPublicRandomness(pd, sess)

	if ks.IsParticipant() {
		ks.sk, err = sess.GetSecretKeyForGroup(pd.Participants) // TODO: could cache the group keys
		if err != nil {
			return nil, err
		}
		ks.privrand = GetProtocolPrivateRandomness(pd, sess)
	}

	if ks.IsAggregator() {
		ks.agg = newShareAggregator(pd, ks.AllocateShare(), ks.proto.AggregatedShares) // TODO: could cache the shares
	}
	return ks, nil
}

func (p *keySwitchProtocol) GenShare(share *Share) error {

	if !p.IsParticipant() {
		return fmt.Errorf("node is not a participant")
	}

	if p.Signature.Type == DEC && p.target == p.self {
		return fmt.Errorf("node is decryption receiver")
	}

	if p.input == nil {
		return fmt.Errorf("no input provided to protocol")
	}

	share.ProtocolID = p.ProtocolID
	share.From = utils.NewSingletonSet(p.self)
	share.Type = p.Signature.Type
	return p.proto.GenShare(p.sk, p.outputKey, p.input, *share)
}

func (p *keySwitchProtocol) Output(agg AggregationOutput) chan Output {
	out := make(chan Output, 1)
	if agg.Error != nil {
		out <- Output{Error: fmt.Errorf("error at aggregation: %w", agg.Error)}
		return out
	}
	res := p.input.CopyNew()
	err := p.proto.Finalize(p.input, res, agg.Share)
	if err != nil {
		out <- Output{Error: fmt.Errorf("error at finalization: %w", err)}
		return out
	}
	p.Logf("finalized protocol")
	out <- Output{Result: res}
	return out
}
