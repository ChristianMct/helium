package setup

import (
	"context"
	"fmt"
	"sync"

	"github.com/ldsec/helium/pkg/objectstore"
	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/protocols"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

type Service struct {
	self pkg.NodeID

	*protocols.Executor
	transport   Transport
	coordinator protocols.Coordinator

	ResultBackend

	l         sync.RWMutex
	completed map[string]protocols.Descriptor
}

type Transport interface {
	// GetAggregationFrom queries the designated node id (typically, the aggregator) for the
	// aggregated share of the designated protocol.
	GetAggregationOutput(context.Context, protocols.Descriptor) (*protocols.AggregationOutput, error)
}

func NewSetupService(ownId pkg.NodeID, executor *protocols.Executor, trans Transport, backend objectstore.ObjectStore) (s *Service, err error) {
	s = new(Service)

	s.self = ownId
	s.Executor = executor
	s.transport = trans
	s.ResultBackend = newObjStoreResultBackend(backend)
	s.completed = make(map[string]protocols.Descriptor)

	return s, nil
}

func (s *Service) RunService(ctx context.Context, coord protocols.Coordinator) {

	s.coordinator = coord

	// processes incoming events from the coordinator
	if s.coordinator.Incoming() != nil { // TODO need a better way
		go func() {
			for ev := range s.coordinator.Incoming() {
				s.Logf("new coordination event: %s", ev)
				switch ev.EventType {
				case protocols.Started:
					var input protocols.Input
					if ev.Descriptor.Signature.Type == protocols.RKG {
						r1Desc := ev.Descriptor
						r1Desc.Signature.Type = protocols.RKG_1
						aggR1, err := s.transport.GetAggregationOutput(ctx, r1Desc)
						if err != nil {
							panic(err)
						}
						if aggR1.Error != nil {
							panic(err)
						}
						input = aggR1.Share
					}
					s.Executor.RunProtocol(ctx, ev.Descriptor, input)
				case protocols.Completed:
					s.l.Lock()
					s.completed[ev.Signature.String()] = ev.Descriptor
					s.l.Unlock()
				case protocols.Failed:
				default:
					panic("unkown event type")
				}
			}
		}()
	}

}

// As helper
func (s *Service) RunProtocol(ctx context.Context, pd protocols.Descriptor) error {

	var input protocols.Input
	if pd.Signature.Type == protocols.RKG {
		aggR1, err := s.GetProtocolOutput(ctx, pd)
		if err != nil { // no r1 share
			pdR1 := pd
			pdR1.Signature.Type = protocols.RKG_1
			aggR1Chan, err := s.Executor.RunProtocol(ctx, pdR1)
			if err != nil {
				return err
			}
			s.coordinator.Outgoing() <- protocols.Event{EventType: protocols.Started, Descriptor: pdR1}
			a := <-aggR1Chan
			if a.Error != nil {
				return a.Error
			}

			aggR1 = &a
			if err := s.ResultBackend.Put(pdR1, a.Share); err != nil {
				return err
			}
			s.coordinator.Outgoing() <- protocols.Event{EventType: protocols.Completed, Descriptor: pdR1}
		}
		input = aggR1.Share
	}

	aggOutChan, err := s.Executor.RunProtocol(ctx, pd, input)
	if err != nil {
		return err
	}

	s.coordinator.Outgoing() <- protocols.Event{EventType: protocols.Started, Descriptor: pd}
	aggOut := <-aggOutChan
	if aggOut.Error != nil {
		return aggOut.Error
	}

	if err := s.ResultBackend.Put(pd, aggOut.Share); err != nil {
		return err
	}

	s.coordinator.Outgoing() <- protocols.Event{EventType: protocols.Completed, Descriptor: pd}

	return nil
}

func (s *Service) GetProtocolOutput(ctx context.Context, pd protocols.Descriptor) (out *protocols.AggregationOutput, err error) {
	// first checks if it has the share locally
	share := protocols.Share{}
	lattigoShare := pd.Signature.Type.Share()
	err = s.ResultBackend.GetShare(pd.Signature, lattigoShare)
	share.MHEShare = lattigoShare
	share.Type = pd.Signature.Type
	share.ProtocolID = pd.ID()

	// otherwise, query the aggregator
	if err != nil {
		if pd.Aggregator == s.self {
			return nil, fmt.Errorf("node is aggregator but has error on backend: %s", err)
		}

		if out, err = s.transport.GetAggregationOutput(ctx, pd); err != nil {
			return nil, err
		}
		s.Logf("queried aggregation for %s", pd.HID())

		share = out.Share
		s.ResultBackend.Put(pd, out.Share)
	}

	return &protocols.AggregationOutput{Share: share}, nil
}

func (s *Service) getOutputForSig(ctx context.Context, sig protocols.Signature) protocols.Output {
	s.l.RLock()
	pd, has := s.completed[sig.String()]
	s.l.RUnlock()
	if !has {
		return protocols.Output{Error: fmt.Errorf("no completed descriptor for sig %s", sig)}
	}

	aggOut, err := s.GetProtocolOutput(ctx, pd)
	if err != nil {
		return protocols.Output{Error: fmt.Errorf("could not retrieve aggrgation output for %s", pd.HID())}
	}

	var input protocols.Input
	if sig.Type == protocols.RKG {
		r1pd := pd
		r1pd.Signature.Type = protocols.RKG_1
		aggOut, err := s.GetProtocolOutput(ctx, pd)
		if err != nil {
			return protocols.Output{Error: fmt.Errorf("could not retrieve aggrgation output for %s", pd.HID())}
		}
		input = aggOut.Share
	}

	return s.Executor.GetOutput(ctx, pd, *aggOut, input)
}

func (s *Service) GetCollectivePublicKey(ctx context.Context) (*rlwe.PublicKey, error) {
	out := s.getOutputForSig(ctx, protocols.Signature{Type: protocols.CKG})
	if out.Error != nil {
		return nil, out.Error
	}
	return out.Result.(*rlwe.PublicKey), nil
}

func (s *Service) GetGaloisKey(ctx context.Context, galEl uint64) (*rlwe.GaloisKey, error) {
	out := s.getOutputForSig(ctx, protocols.Signature{Type: protocols.RTG, Args: map[string]string{"GalEl": fmt.Sprintf("%d", galEl)}})
	if out.Error != nil {
		return nil, out.Error
	}
	return out.Result.(*rlwe.GaloisKey), nil
}

func (s *Service) GetRelinearizationKey(ctx context.Context) (*rlwe.RelinearizationKey, error) {
	out := s.getOutputForSig(ctx, protocols.Signature{Type: protocols.RKG})
	if out.Error != nil {
		return nil, out.Error
	}
	return out.Result.(*rlwe.RelinearizationKey), nil
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

// // storeProtocolOutput stores the protocol's output in the ObjectStore of the node.
// func (s *Service) storeProtocolOutput(outputs chan struct {
// 	protocols.Descriptor
// 	protocols.Output
// }, sess *pkg.Session) {
// 	for output := range outputs {
// 		// s.Logf("[Store] Storing output for protocol %s under %s", output.Descriptor.ID, output.Signature.String())

// 		if output.Result != nil {
// 			switch res := output.Result.(type) {
// 			case *rlwe.PublicKey:
// 				if err := sess.ObjectStore.Store(output.Signature.String(), res); err != nil {
// 					s.Logf("error on Public Key store: %s", err)
// 				}
// 			case *rlwe.RelinearizationKey:
// 				if err := sess.ObjectStore.Store(output.Signature.String(), res); err != nil {
// 					s.Logf("error on Relinearization Key store: %s", err)
// 				}
// 			case *rlwe.GaloisKey:
// 				if err := sess.ObjectStore.Store(output.Signature.String(), res); err != nil {
// 					s.Logf("error on Rotation Key Store: %s", err)
// 				}
// 			case *drlwe.RelinearizationKeyGenShare:
// 				if err := sess.ObjectStore.Store(output.Signature.Type.String(), res); err != nil {
// 					s.Logf("error on Relinearization Key Share store: %s", err)
// 				}
// 			default:
// 				s.Logf("got output for protocol %s: %v", output.ID(), output)
// 			}
// 		}
// 	}
// }
