package protocols

import (
	"fmt"
	"log"
	"slices"

	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v4/drlwe"
)

type cpkProtocol struct {
	patProtocol
	kg  MHEKeygenProtocol
	crp CRP
}

func NewKeygenProtocol(pd Descriptor, sess *pkg.Session, inputs ...Input) (Instance, error) {

	prot, err := newPATProtocol(pd, sess)
	if err != nil {
		return nil, err
	}

	p := &cpkProtocol{
		patProtocol: *prot,
	}

	p.kg = p.proto.(MHEKeygenProtocol)

	switch pd.Signature.Type {
	case CKG:
	case RTG:
	case RKG_1:
	case RKG:

		if len(inputs) != 1 {
			return nil, fmt.Errorf("protocol signature %s requires an input", pd.Signature.Type)
		}

		rkgR1Share, isShare := inputs[0].(Share)
		if !isShare {
			return nil, fmt.Errorf("protocol signature %s requires input of type %T, got %T", pd.Signature.Type, rkgR1Share, inputs[0])
		}

		p.crp = rkgR1Share.MHEShare

	default:
		err = fmt.Errorf("unknown protocol type: %s", pd.Signature.Type)
	}
	if err != nil {
		return nil, err
	}

	return p, nil
}

func (p *cpkProtocol) GenShare(share *Share) error {

	if !p.IsParticipant() {
		return fmt.Errorf("node is not a participant")
	}

	if p.crp == nil {
		var err error
		p.crp, err = p.kg.ReadCRP(p.pubrand)
		if err != nil {
			return err
		}
	}

	p.Logf("[%s] generating share", p.pd.HID())
	share.ProtocolID = p.id
	share.From = utils.NewSingletonSet(p.self)
	share.ProtocolType = p.pd.Type
	return p.kg.GenShare(p.sk, p.crp, *share)
}

func (p *cpkProtocol) Output(agg AggregationOutput) chan Output {
	out := make(chan Output, 1)
	if agg.Error != nil {
		out <- Output{Error: fmt.Errorf("error at aggregation: %w", agg.Error)}
		return out
	}

	if p.crp == nil {
		var err error
		p.crp, err = p.kg.ReadCRP(p.pubrand)
		if err != nil {
			out <- Output{Error: fmt.Errorf("error at finalization: %w", err)}
			return out
		}
	}

	res, err := p.kg.Finalize(p.crp, agg.Share)
	if err != nil {
		out <- Output{Error: fmt.Errorf("error at finalization: %w", err)}
		return out
	}
	p.Logf("finalized protocol")
	out <- Output{Result: res}
	return out
}

func (p *patProtocol) ID() ID {
	return p.id
}

func (p *patProtocol) Descriptor() Descriptor {
	return p.pd
}

func (p *cpkProtocol) AllocateShare() Share {
	return p.kg.AllocateShare()
}

func (p *skgProtocol) AllocateShare() Share {
	return p.proto.AllocateShare()
}

func (p *keySwitchProtocol) AllocateShare() Share {
	return p.ks.AllocateShare()
}

func (p *patProtocol) HasShareFrom(nid pkg.NodeID) bool {
	return !p.agg.Missing().Contains(nid)
}

func (p *patProtocol) IsAggregator() bool {
	return p.pd.Aggregator == p.self || p.pd.Signature.Type == SKG
}

func (p *patProtocol) IsParticipant() bool {
	return slices.Contains(p.pd.Participants, p.self)
}

func (p *patProtocol) HasRole() bool {
	return p.IsAggregator() || p.IsParticipant()
}

func (p *patProtocol) Logf(msg string, v ...any) {
	if !protocolLogging {
		return
	}
	log.Printf("%s | [%s] %s\n", p.self, p.HID(), fmt.Sprintf(msg, v...))
}

func (s Share) Copy() Share {
	switch st := s.MHEShare.(type) {
	case *drlwe.PublicKeyGenShare:
		return Share{ShareMetadata: s.ShareMetadata, MHEShare: &drlwe.PublicKeyGenShare{Value: *st.Value.CopyNew()}}
	default:
		panic("not implemented") // TODO: implement on Lattigo side ?
	}
}

func (s Share) MarshalBinary() ([]byte, error) {
	return s.MHEShare.MarshalBinary()
}

func (s Share) UnmarshalBinary(data []byte) error {
	return s.MHEShare.UnmarshalBinary(data)
}
