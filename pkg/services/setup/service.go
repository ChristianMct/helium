package setup

import (
	"context"

	"github.com/ldsec/helium/pkg/objectstore"
	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/protocols"
	"github.com/tuneinsight/lattigo/v4/drlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

const parallelAggregation int = 10
const parallelParticipation int = 10

const numProtoPerNode int = 3

type Service struct {
	self pkg.NodeID

	sessions    pkg.SessionProvider
	transport   protocols.Transport
	coordinator protocols.Coordinator

	*protocols.Executor
}

func NewSetupService(ownId pkg.NodeID, sessions pkg.SessionProvider, trans protocols.Transport, coord protocols.Coordinator, objStore objectstore.ObjectStore) (s *Service, err error) {
	s = new(Service)

	s.self = ownId
	s.sessions = sessions
	s.transport = trans
	s.coordinator = coord
	s.Executor, err = protocols.NewExectutor(ownId, sessions, trans, coord, objStore)
	if err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Service) RunService(ctx context.Context) {

	s.Executor.RunService(ctx)

}

func (s *Service) NodeID() pkg.NodeID {
	return s.self
}

// filterSignatureList splits a SignatureList into two lists based on the presence of the protocol's output in the ObjectStore.
func (s *Service) filterSignatureList(sl SignatureList) (noResult, hasResult SignatureList) {
	noResult, hasResult = make(SignatureList, 0), make(SignatureList, 0)
	for _, sig := range sl {
		has, err := s.ResultBackend.Has(sig)
		if err != nil {
			panic(err)
		}
		if has {
			hasResult = append(hasResult, sig)
		} else {
			noResult = append(noResult, sig)
		}
	}
	return
}

// storeProtocolOutput stores the protocol's output in the ObjectStore of the node.
func (s *Service) storeProtocolOutput(outputs chan struct {
	protocols.Descriptor
	protocols.Output
}, sess *pkg.Session) {
	for output := range outputs {
		// s.Logf("[Store] Storing output for protocol %s under %s", output.Descriptor.ID, output.Signature.String())

		if output.Result != nil {
			switch res := output.Result.(type) {
			case *rlwe.PublicKey:
				if err := sess.ObjectStore.Store(output.Signature.String(), res); err != nil {
					s.Logf("error on Public Key store: %s", err)
				}
			case *rlwe.RelinearizationKey:
				if err := sess.ObjectStore.Store(output.Signature.String(), res); err != nil {
					s.Logf("error on Relinearization Key store: %s", err)
				}
			case *rlwe.GaloisKey:
				if err := sess.ObjectStore.Store(output.Signature.String(), res); err != nil {
					s.Logf("error on Rotation Key Store: %s", err)
				}
			case *drlwe.RelinearizationKeyGenShare:
				if err := sess.ObjectStore.Store(output.Signature.Type.String(), res); err != nil {
					s.Logf("error on Relinearization Key Share store: %s", err)
				}
			default:
				s.Logf("got output for protocol %s: %v", output.ID(), output)
			}
		}
	}
}
