package setup

import (
	"fmt"

	"github.com/ldsec/helium/pkg/protocols"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

func (s *Service) GetCollectivePublicKey() (*rlwe.PublicKey, error) {
	aggShare := protocols.CKG.Share()
	sig := protocols.Signature{Type: protocols.CKG}
	sess, ok := s.sessions.GetSessionFromID("test-session")
	if !ok {
		return nil, fmt.Errorf("session does not exist")
	}

	err := s.ResultBackend.GetShare(sig, aggShare)

	var proto protocols.Instance
	proto, err = protocols.NewProtocol(protocols.Descriptor{Signature: sig}, sess) // TODO this resamples the CRP (could be done while waiting for agg)
	if err != nil {
		panic(err)
	}

	out := <-proto.Output(protocols.AggregationOutput{Share: protocols.Share{MHEShare: aggShare}})
	return out.Result.(*rlwe.PublicKey), nil
}
