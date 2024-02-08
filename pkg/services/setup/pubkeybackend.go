package setup

import (
	"context"
	"fmt"

	"github.com/ldsec/helium/pkg/protocols"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

func (s *Service) getKeyFromProto(ctx context.Context, sig protocols.Signature) (key interface{}, err error) {
	sess, ok := s.sessions.GetSessionFromContext(ctx)
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

	if pd.Signature.Type == protocols.RKG_2 {
		aggShareR1 := sig.Type.Share()
		err = s.ResultBackend.GetShare(protocols.Signature{Type: protocols.RKG_1}, aggShareR1)
		if err != nil {
			return nil, err
		}
		proto.Init(aggShareR1)
	} else {
		crp, err := proto.ReadCRP()
		if err != nil {
			panic(err)
		}
		proto.Init(crp)
	}

	out := <-proto.Output(protocols.AggregationOutput{Share: protocols.Share{MHEShare: aggShare}})
	if out.Error != nil {
		return nil, out.Error
	}
	return out.Result, nil
}

func (s *Service) GetCollectivePublicKey(ctx context.Context) (*rlwe.PublicKey, error) {
	key, err := s.getKeyFromProto(ctx, protocols.Signature{Type: protocols.CKG})
	if err != nil {
		return nil, err
	}
	return key.(*rlwe.PublicKey), nil
}

func (s *Service) GetGaloisKey(ctx context.Context, galEl uint64) (*rlwe.GaloisKey, error) {
	key, err := s.getKeyFromProto(ctx, protocols.Signature{Type: protocols.RTG, Args: map[string]string{"GalEl": fmt.Sprintf("%d", galEl)}})
	if err != nil {
		return nil, err
	}
	return key.(*rlwe.GaloisKey), nil
}

func (s *Service) GetRelinearizationKey(ctx context.Context) (*rlwe.RelinearizationKey, error) {
	key, err := s.getKeyFromProto(ctx, protocols.Signature{Type: protocols.RKG_2})
	if err != nil {
		return nil, err
	}
	return key.(*rlwe.RelinearizationKey), nil
}
