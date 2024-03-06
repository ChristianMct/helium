package setup

import (
	"context"
	"fmt"
	"log"

	"github.com/ldsec/helium/pkg/objectstore"
	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/protocols"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

type ServiceConfig struct {
	Protocols protocols.ExecutorConfig
}

type Service struct {
	self pkg.NodeID

	execuctor *protocols.Executor
	transport Transport

	// protocols.Coordinator
	incoming, outgoing chan protocols.Event

	ResultBackend

	//l         sync.RWMutex
	completed *protocols.CompleteMap
}

type Transport interface {
	protocols.Transport
	// GetAggregationFrom queries the designated node id (typically, the aggregator) for the
	// aggregated share of the designated protocol.
	GetAggregationOutput(context.Context, protocols.Descriptor) (*protocols.AggregationOutput, error)
}

func NewSetupService(ownId pkg.NodeID, sessions pkg.SessionProvider, conf ServiceConfig, trans Transport, backend objectstore.ObjectStore) (s *Service, err error) {
	s = new(Service)

	s.self = ownId
	s.execuctor, err = protocols.NewExectutor(conf.Protocols, s.self, sessions, s, s.GetInputs, trans)
	if err != nil {
		return nil, err
	}
	s.transport = trans
	s.ResultBackend = newObjStoreResultBackend(backend)
	s.completed = protocols.NewCompletedProt(nil)

	s.incoming = make(chan protocols.Event)
	s.outgoing = make(chan protocols.Event)

	return s, nil
}

func (s *Service) processEvent(ev protocols.Event) {

	if !ev.IsSetupEvent() {
		panic("non-setup event sent to setup service")
	}

	switch ev.EventType {
	case protocols.Started:
	case protocols.Completed:
		err := s.completed.CompletedProtocol(ev.Descriptor)
		if err != nil {
			panic(err)
		}
	case protocols.Failed:
	default:
		panic("unkown event type")
	}
}

func (s *Service) Init(ctx context.Context, complPd, runPd []protocols.Descriptor) error {

	for _, cpd := range complPd {

		if !cpd.Signature.Type.IsSetup() {
			continue
		}
		if err := s.completed.CompletedProtocol(cpd); err != nil {
			return err
		}
	}

	for _, rpd := range runPd {
		if !rpd.Signature.Type.IsSetup() {
			continue
		}
		s.incoming <- protocols.Event{EventType: protocols.Executing, Descriptor: rpd} // sends a protocol started event downstream
	}

	return nil
}

func (s *Service) Run(ctx context.Context, coord protocols.Coordinator) error {

	// processes incoming events from the coordinator
	upstreamDone := make(chan struct{})
	if coord.Incoming() != nil { // TODO need a better way
		go func() {
			for ev := range coord.Incoming() {
				s.Logf("new coordination event: %s", ev)
				s.processEvent(ev) // update local state
				s.incoming <- ev   // pass the event downstream
			}
			close(upstreamDone)
		}()
	}

	// process downstream outgoing events
	downstreamDone := make(chan struct{})
	go func() {
		for ev := range s.outgoing {
			s.processEvent(ev)     // update local state
			coord.Outgoing() <- ev // pass the event upstream
		}
		close(downstreamDone)
	}()

	executorRunReturned := make(chan struct{})
	go func() {
		err := s.execuctor.Run(ctx)
		if err != nil {
			panic(err) // TODO: return in Run
		}
		close(executorRunReturned)
	}()

	<-upstreamDone
	s.Logf("upstream coordinator is done, closing downstream")
	close(s.incoming) // closing downstream

	<-executorRunReturned
	s.Logf("executor Run method returned")

	<-downstreamDone
	close(coord.Outgoing()) // closing upstream
	s.Logf("downstream coordinator is done, service.Run return")
	return nil
}

// As helper
func (s *Service) RunSignature(ctx context.Context, sig protocols.Signature) error {

	err := s.execuctor.RunSignature(ctx, sig, s.Put)
	if err != nil {
		return err
	}

	return nil
}

func (s *Service) GetInputs(ctx context.Context, pd protocols.Descriptor) (protocols.Input, error) {

	if pd.Signature.Type != protocols.RKG {
		return nil, nil
	}

	aggOutR1, err := s.GetProtocolOutput(ctx, protocols.Descriptor{Signature: protocols.Signature{Type: protocols.RKG_1}, Participants: pd.Participants, Aggregator: pd.Aggregator})
	if err != nil {
		return nil, err
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
	if err == nil {
		return &protocols.AggregationOutput{Share: share, Descriptor: pd}, nil
	}

	// otherwise, query the aggregator or run the protocol
	if pd.Aggregator != s.self {
		if out, err = s.transport.GetAggregationOutput(ctx, pd); err != nil {
			return nil, fmt.Errorf("error when queriying transport for aggregation output: %w", err)
		}
	} else {
		aggOutC := make(chan protocols.AggregationOutput, 1)
		err := s.execuctor.RunDescriptorAsAggregator(ctx, pd, func(ctx context.Context, ao protocols.AggregationOutput) error {
			aggOutC <- ao
			return nil
		})
		if err != nil {
			return nil, err
		}
		aggOut := <-aggOutC
		out = &aggOut
		err = s.ResultBackend.Put(pd, aggOut.Share)
		if err != nil {
			return nil, err
		}

	}

	return out, nil
}

func (s *Service) getOutputForSig(ctx context.Context, sig protocols.Signature) protocols.Output {

	pd, err := s.completed.AwaitCompletedDescriptorFor(sig)
	if err != nil {
		return protocols.Output{Error: fmt.Errorf("error while waiting for signature: %w", err)}
	}

	aggOut, err := s.GetProtocolOutput(ctx, *pd)
	if err != nil {
		return protocols.Output{Error: fmt.Errorf("could not retrieve aggrgation output for %s: %w", pd.HID(), err)}
	}

	return s.execuctor.GetOutput(ctx, *aggOut)
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

func (s *Service) Register(nid pkg.NodeID) error {
	return s.execuctor.Register(nid)
}

func (s *Service) Unregister(nid pkg.NodeID) error {
	return s.execuctor.Unregister(nid)
}

func (s *Service) Logf(msg string, v ...any) {
	log.Printf("%s | [setup] %s\n", s.self, fmt.Sprintf(msg, v...))
}
