package setup

import (
	"fmt"

	"github.com/ldsec/helium/pkg/protocols"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

func (s *Service) getKeyFromProto(sig protocols.Signature) (key interface{}, err error) {
	sess, ok := s.sessions.GetSessionFromID("test-session")
	if !ok {
		return nil, fmt.Errorf("session does not exist")
	}

	pd, err := s.ResultBackend.GetProtocolDesc(sig)
	if err != nil {
		return nil, err
	}

	aggShare := sig.Type.Share()
	err = s.ResultBackend.GetShare(sig, aggShare)
	if err != nil {
		return nil, err
	}

	var proto protocols.Instance
	proto, err = protocols.NewProtocol(pd, sess) // TODO this resamples the CRP (could be done while waiting for agg)
	if err != nil {
		panic(err)
	}

	out := <-proto.Output(protocols.AggregationOutput{Share: protocols.Share{MHEShare: aggShare}})
	if out.Error != nil {
		return nil, out.Error
	}
	return out.Result, nil
}

func (s *Service) GetCollectivePublicKey() (*rlwe.PublicKey, error) {
	key, err := s.getKeyFromProto(protocols.Signature{Type: protocols.CKG})
	if err != nil {
		return nil, err
	}
	return key.(*rlwe.PublicKey), nil
}

func (s *Service) GetGaloisKey(galEl uint64) (*rlwe.GaloisKey, error) {
	key, err := s.getKeyFromProto(protocols.Signature{Type: protocols.RTG, Args: map[string]string{"GalEl": fmt.Sprintf("%d", galEl)}})
	if err != nil {
		return nil, err
	}
	return key.(*rlwe.GaloisKey), nil
}

func (s *Service) GetRelinearizationKey() (*rlwe.RelinearizationKey, error) {
	key, err := s.getKeyFromProto(protocols.Signature{Type: protocols.RKG_2})
	if err != nil {
		return nil, err
	}
	return key.(*rlwe.RelinearizationKey), nil
}
