// package setup implements the MHE setup phase as a service.
// This serices executes the key generation protocols and makes their
// outputs available.
package setup

import (
	"context"
	"fmt"
	"log"

	"github.com/ldsec/helium/helium"
	"github.com/ldsec/helium/helium/objectstore"
	"github.com/ldsec/helium/helium/protocols"
	"github.com/ldsec/helium/helium/session"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

// ServiceConfig is the configuration for the setup service.
type ServiceConfig struct {
	Protocols protocols.ExecutorConfig
}

// Service represents an instance of the setup service.
type Service struct {
	self helium.NodeID

	sessions session.SessionProvider

	execuctor *protocols.Executor
	transport Transport

	// protocols.Coordinator
	incoming, outgoing chan protocols.Event

	resBackend *objStoreResultBackend

	//l         sync.RWMutex
	completed *protocols.CompleteMap
}

// Transport defines the transport interface needed by the setup service.
// In the current implementation, this corresponds to the helper interface.
type Transport interface {
	protocols.Transport
	// GetAggregationOutput returns the aggregation output for the given protocol.
	GetAggregationOutput(context.Context, protocols.Descriptor) (*protocols.AggregationOutput, error)
}

// NewSetupService creates a new setup service.
func NewSetupService(ownId helium.NodeID, sessions session.SessionProvider, conf ServiceConfig, trans Transport, backend objectstore.ObjectStore) (s *Service, err error) {
	s = new(Service)

	s.self = ownId
	s.sessions = sessions
	s.execuctor, err = protocols.NewExectutor(conf.Protocols, s.self, sessions, s, s.GetProtocolInput, trans)
	if err != nil {
		return nil, err
	}
	s.transport = trans
	s.resBackend = newObjStoreResultBackend(backend)
	s.completed = protocols.NewCompletedProt(nil)

	s.incoming = make(chan protocols.Event)
	s.outgoing = make(chan protocols.Event)

	return s, nil
}

// Init initializes the setup service from the current state of the protocols.
// Completed protocols are marked as such, and running protocols are queued for execution.
func (s *Service) Init(ctx context.Context, complPd, runPd []protocols.Descriptor) error {

	// mark completed protocols
	for _, cpd := range complPd {

		if !cpd.Signature.Type.IsSetup() {
			continue
		}
		if err := s.completed.CompletedProtocol(cpd); err != nil {
			return err
		}
	}

	// queue running protocols
	for _, rpd := range runPd {
		if !rpd.Signature.Type.IsSetup() {
			continue
		}
		s.incoming <- protocols.Event{EventType: protocols.Executing, Descriptor: rpd} // sends a protocol started event downstream
	}

	return nil
}

// Run runs the setup service as coordinated by the given coordinator.
// It processes and forwards incoming events from upstream (coordinator) and downstream (executor).
// It returns when the upstream coordinator is done and the downstream executor is done.
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

// RunSignature queues the given signature for execution. This method is called by the helper.
func (s *Service) RunSignature(ctx context.Context, sig protocols.Signature) error {

	err := s.execuctor.RunSignature(ctx, sig, s.AggregationOutputHandler)
	if err != nil {
		return err
	}

	return nil
}

// PublicKeyBackend interface implementation

// GetCollectivePublicKey returns the collective public key when available.
// The method blocks until the corresponding protocol completes.
func (s *Service) GetCollectivePublicKey(ctx context.Context) (*rlwe.PublicKey, error) {
	out, err := s.getOutputForSig(ctx, protocols.Signature{Type: protocols.CKG})
	if err != nil {
		return nil, err
	}
	return out.Result.(*rlwe.PublicKey), nil
}

// GetGaloisKey returns the Galois key for the given Galois element when available.
// The method blocks until the corresponding protocol completes.
func (s *Service) GetGaloisKey(ctx context.Context, galEl uint64) (*rlwe.GaloisKey, error) {
	out, err := s.getOutputForSig(ctx, protocols.Signature{Type: protocols.RTG, Args: map[string]string{"GalEl": fmt.Sprintf("%d", galEl)}})
	if err != nil {
		return nil, err
	}
	return out.Result.(*rlwe.GaloisKey), nil
}

// GetRelinearizationKey returns the relinearization key when available.
// The method blocks until the corresponding protocol completes.
func (s *Service) GetRelinearizationKey(ctx context.Context) (*rlwe.RelinearizationKey, error) {
	out, err := s.getOutputForSig(ctx, protocols.Signature{Type: protocols.RKG})
	if err != nil {
		return nil, err
	}
	return out.Result.(*rlwe.RelinearizationKey), nil
}

func (s *Service) getOutputForSig(ctx context.Context, sig protocols.Signature) (*protocols.Output, error) {

	pd, err := s.completed.AwaitCompletedDescriptorFor(sig)
	if err != nil {
		return nil, fmt.Errorf("error while waiting for signature: %w", err)
	}

	aggOut, err := s.GetAggregationOutput(ctx, *pd)
	if err != nil {
		return nil, fmt.Errorf("could not retrieve aggrgation output for %s: %w", pd.HID(), err)
	}

	sess, has := s.sessions.GetSessionFromContext(ctx)
	if !has {
		return nil, fmt.Errorf("session not found in context")
	}

	out := protocols.AllocateOutput(sig, sess.Params.Parameters) // TODO cache ?
	err = s.execuctor.GetOutput(ctx, *aggOut, out)
	if err != nil {
		return nil, fmt.Errorf("error while getting output: %w", err)
	}

	return &protocols.Output{Descriptor: *pd, Result: out}, nil
}

// GetProtocolInput returns the protocol inputs for the given protocol descriptor.
// It is meant to be passed to a protocols.Executor as a protocols.InputProvider method.
func (s *Service) GetProtocolInput(ctx context.Context, pd protocols.Descriptor) (protocols.Input, error) {

	sess, has := s.sessions.GetSessionFromContext(ctx)
	if !has {
		return nil, fmt.Errorf("session not found in context")
	}

	switch pd.Signature.Type {
	case protocols.CKG, protocols.RTG, protocols.RKG_1:
		p, err := protocols.NewProtocol(pd, sess) // TODO: cache and reuse ?
		if err != nil {
			return nil, err
		}
		return p.ReadCRP()
	case protocols.RKG:
		aggOutR1, err := s.GetAggregationOutput(ctx, protocols.Descriptor{Signature: protocols.Signature{Type: protocols.RKG_1}, Participants: pd.Participants, Aggregator: pd.Aggregator})
		if err != nil {
			return nil, err
		}
		return aggOutR1.Share.MHEShare, nil // TODO: regresion on MHEShare
	default:
		return nil, fmt.Errorf("no input for this protocol")
	}
}

// GetAggregationOutput returns the aggregation output for the given protocol descriptor.
// If the output is not available locally, it queries the protocol's aggregator.
// If called at the aggregator, it runs the protocol and returns the output.
func (s *Service) GetAggregationOutput(ctx context.Context, pd protocols.Descriptor) (out *protocols.AggregationOutput, err error) {
	// first checks if it has the share locally
	out, err = s.getAggregationOutputFromBackend(ctx, pd)
	if err == nil {
		return out, nil
	}

	// otherwise, query the aggregator or run the protocol
	if pd.Aggregator != s.self {
		if out, err = s.transport.GetAggregationOutput(ctx, pd); err != nil {
			return nil, fmt.Errorf("error when queriying transport for aggregation output: %w", err)
		}
	} else {
		// TODO: prevent double run of protocol
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
		err = s.resBackend.Put(ctx, pd, aggOut.Share)
		if err != nil {
			return nil, err
		}

	}

	return out, nil
}

func (s *Service) getAggregationOutputFromBackend(ctx context.Context, pd protocols.Descriptor) (*protocols.AggregationOutput, error) {
	share := protocols.Share{}
	lattigoShare := pd.Signature.Type.Share()
	err := s.resBackend.GetShare(ctx, pd.Signature, lattigoShare)
	if err != nil {
		return nil, err
	}
	share.MHEShare = lattigoShare
	share.ProtocolType = pd.Signature.Type
	share.ProtocolID = pd.ID()
	return &protocols.AggregationOutput{Share: share, Descriptor: pd}, nil
}

// AggregationOutputHandler is called when a protocol aggregation completes.
// It is meant to be passed to a protocols.Executor as a protocols.AggregationOutputHandler method.
func (s *Service) AggregationOutputHandler(ctx context.Context, aggOut protocols.AggregationOutput) error {
	return s.resBackend.Put(ctx, aggOut.Descriptor, aggOut.Share)
}

// NodeID returns the node ID associated with this service.
func (s *Service) NodeID() helium.NodeID {
	return s.self
}

// protocols.Coordinator interface implementation

// Incoming returns the incoming event channel for the protocols.Coordinator interface.
func (s *Service) Incoming() <-chan protocols.Event {
	return s.incoming
}

// Outgoing returns the outgoing event channel for the protocols.Coordinator interface.
func (s *Service) Outgoing() chan<- protocols.Event {
	return s.outgoing
}

// Register registers a connected node to the service.
func (s *Service) Register(nid helium.NodeID) error {
	return s.execuctor.Register(nid)
}

// Unregister unregisters a disconnected node from the service
func (s *Service) Unregister(nid helium.NodeID) error {
	return s.execuctor.Unregister(nid)
}

// Logf prints a log message.
func (s *Service) Logf(msg string, v ...any) {
	log.Printf("%s | [setup] %s\n", s.self, fmt.Sprintf(msg, v...))
}
