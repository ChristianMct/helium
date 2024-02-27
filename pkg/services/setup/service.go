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
	transport Transport

	// protocols.Coordinator
	incoming, outgoing chan protocols.Event

	ResultBackend

	l         sync.RWMutex
	completed map[string]protocols.Descriptor
}

type Transport interface {
	protocols.Transport
	// GetAggregationFrom queries the designated node id (typically, the aggregator) for the
	// aggregated share of the designated protocol.
	GetAggregationOutput(context.Context, protocols.Descriptor) (*protocols.AggregationOutput, error)
}

func NewSetupService(ownId pkg.NodeID, sessions pkg.SessionProvider, trans Transport, backend objectstore.ObjectStore) (s *Service, err error) {
	s = new(Service)

	s.self = ownId
	s.Executor, err = protocols.NewExectutor(s.self, sessions, s, s.GetInputs, s, trans)
	s.transport = trans
	s.ResultBackend = newObjStoreResultBackend(backend)
	s.completed = make(map[string]protocols.Descriptor)

	s.incoming = make(chan protocols.Event)
	s.outgoing = make(chan protocols.Event)

	return s, nil
}

func (s *Service) Run(ctx context.Context, coord protocols.Coordinator) {

	// processes incoming events from the coordinator
	upstreamDone := make(chan struct{})
	if coord.Incoming() != nil { // TODO need a better way
		go func() {
			for ev := range coord.Incoming() {
				s.Logf("new coordination event: %s", ev)
				switch ev.EventType {
				case protocols.Started:
				case protocols.Completed:
					s.l.Lock()
					s.completed[ev.Signature.String()] = ev.Descriptor
					s.l.Unlock()
				case protocols.Failed:
				default:
					panic("unkown event type")
				}
				s.incoming <- ev
			}
			close(upstreamDone)
		}()
	}

	// process outgoing events
	downstreamDone := make(chan struct{})
	go func() {
		for ev := range s.outgoing {
			coord.Outgoing() <- ev
		}
		close(downstreamDone)
	}()

	go s.Executor.Run(ctx)

	<-upstreamDone
	s.Logf("upstream coordinator is done, closing downstream")
	close(s.incoming) // closing downstream
	<-downstreamDone
	s.Logf("downstream coordinator is done, service.Run return")
}

// As helper
func (s *Service) RunProtocol(ctx context.Context, sig protocols.Signature) error {

	aggOut, err := s.Executor.RunSignatureAsAggregator(ctx, sig)
	if err != nil {
		return err
	}

	return (<-aggOut).Error
}

func (s *Service) GetInputs(ctx context.Context, pd protocols.Descriptor) (protocols.Input, error) {

	if pd.Signature.Type != protocols.RKG {
		return nil, nil
	}

	r1pd := pd
	r1pd.Signature.Type = protocols.RKG_1

	var aggOutR1 *protocols.AggregationOutput
	var err error
	if pd.Aggregator != s.self {
		if aggOutR1, err = s.transport.GetAggregationOutput(ctx, r1pd); err != nil {
			return nil, fmt.Errorf("error when retrieving aggregation output: %w", err)
		}
	} else {
		aggOutC, err := s.Executor.RunDescriptorAsAggregator(ctx, r1pd)
		if err != nil {
			return nil, err
		}
		aggOut := <-aggOutC
		aggOutR1 = &aggOut
	}

	return aggOutR1.Share, nil
}

// Reszlts and Backend // TODO messy

func (s *Service) Put(ctx context.Context, aggOut protocols.AggregationOutput) error {
	return s.ResultBackend.Put(aggOut.Descriptor, aggOut.Share)
}

func (s *Service) Get(ctx context.Context, pd protocols.Descriptor) (*protocols.AggregationOutput, error) {
	share := protocols.Share{}
	lattigoShare := pd.Signature.Type.Share()
	err := s.ResultBackend.GetShare(pd.Signature, lattigoShare)
	if err != nil {
		return nil, err
	}
	share.MHEShare = lattigoShare
	share.Type = pd.Signature.Type
	share.ProtocolID = pd.ID()
	return &protocols.AggregationOutput{Share: share, Descriptor: pd}, nil
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

	return &protocols.AggregationOutput{Share: share, Descriptor: pd}, nil
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

	return s.Executor.GetOutput(ctx, *aggOut)
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

func (s *Service) Incoming() <-chan protocols.Event {
	return s.incoming
}

func (s *Service) Outgoing() chan<- protocols.Event {
	return s.outgoing
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
