// Package setup implements the MHE setup phase as a service.
// This serices executes the key generation protocols and makes their
// outputs available.
package setup

import (
	"context"
	"fmt"
	"log"

	"github.com/ChristianMct/helium/coordinator"
	"github.com/ChristianMct/helium/objectstore"
	"github.com/ChristianMct/helium/protocol"
	"github.com/ChristianMct/helium/session"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
)

// ServiceConfig is the configuration for the setup service.
type ServiceConfig struct {
	Protocols protocol.ExecutorConfig
}

// Service represents an instance of the setup service.
type Service struct {
	self session.NodeID

	sessions session.SessionProvider

	executor  *protocol.Executor
	transport Transport

	// protocols.Coordinator
	incoming, outgoing chan protocol.Event

	resBackend *objStoreResultBackend

	//l         sync.RWMutex
	completed *protocol.CompleteMap
}

type Event struct {
	protocol.Event
}

type Coordinator coordinator.Coordinator[Event]

// NewSetupService creates a new setup service.
func NewSetupService(ownID session.NodeID, sessions session.SessionProvider, conf ServiceConfig, backend objectstore.ObjectStore) (s *Service, err error) {
	s = new(Service)

	s.self = ownID
	s.sessions = sessions

	s.incoming = make(chan protocol.Event)
	s.outgoing = make(chan protocol.Event)

	s.executor, err = protocol.NewExectutor(conf.Protocols, s.self, sessions, &coordinator.Channel[protocol.Event]{Incoming: s.incoming, Outgoing: s.outgoing}, s.GetProtocolInput)
	if err != nil {
		return nil, err
	}

	s.resBackend = newObjStoreResultBackend(backend)
	s.completed = protocol.NewCompletedProt(nil)

	return s, nil
}

func recoverPresentState(events <-chan Event, present int) (completePd, failPd, runningPd []protocol.Descriptor, err error) {

	if present == 0 {
		return
	}

	var current int
	runProto := make(map[protocol.ID]protocol.Descriptor)
	for ev := range events {
		pid := ev.ID()
		if !ev.Signature.Type.IsSetup() {
			return nil, nil, nil, fmt.Errorf("non-setup event %s", ev.HID())
		}

		switch ev.EventType {
		case protocol.Started:
			runProto[pid] = ev.Descriptor
		case protocol.Executing:
			if _, has := runProto[pid]; !has {
				err = fmt.Errorf("inconsisted state, protocol %s execution event before start", ev.HID())
				return
			}
		case protocol.Completed, protocol.Failed:
			if _, has := runProto[pid]; !has {
				err = fmt.Errorf("inconsisted state, protocol %s termination event before start", ev.HID())
				return
			}
			delete(runProto, pid)
			if ev.EventType == protocol.Completed {
				completePd = append(completePd, ev.Descriptor)
			} else {
				failPd = append(failPd, ev.Descriptor)
			}
		}
		//log.Println("LOG", ev)

		current++
		if current == present {
			break
		}
	}

	for _, rp := range runProto {
		runningPd = append(runningPd, rp)
	}

	return
}

// Init initializes the setup service from the current state of the protocols.
// Completed protocols are marked as such, and running protocols are queued for execution.
func (s *Service) init(upstreamInc <-chan Event, present int) error { // TODO: make private

	var complPd, failPd, runPd, err = recoverPresentState(upstreamInc, present)
	if err != nil {
		return err
	}

	// mark completed protocols
	for _, cpd := range complPd {
		if err := s.completed.CompletedProtocol(cpd); err != nil {
			return err
		}
	}

	// queue running protocols
	for _, rpd := range runPd {
		s.incoming <- protocol.Event{EventType: protocol.Started, Descriptor: rpd} // sends a protocol started event downstream
	}

	s.Logf("service initialized with %d completed, %d failed and %d running protocols (present=%d)", len(complPd), len(failPd), len(runPd), present)

	return nil
}

// Run runs the setup service as coordinated by the given coordinator.
// It processes and forwards incoming events from upstream (coordinator) and downstream (executor).
// It returns when the upstream coordinator is done and the downstream executor is done.
func (s *Service) Run(ctx context.Context, upstream Coordinator, trans Transport) error {

	s.Logf("starting service.Run")

	s.transport = trans

	runCtx, cancelRunCtx := context.WithCancel(session.ContextWithNodeID(ctx, s.self))
	defer cancelRunCtx()

	// registers to the upstream coordinator
	upstreamChan, present, err := upstream.Register(runCtx)
	if err != nil {
		return err
	}

	// starts the executor (init sends events to its queue)
	executorRunReturned := make(chan struct{})
	go func() {
		err := s.executor.Run(runCtx, s.transport)
		if err != nil {
			panic(err) // TODO: return in Run
		}
		close(executorRunReturned)
	}()

	// initializes the service from the current state of the protocols
	if err = s.init(upstreamChan.Incoming, present); err != nil {
		return fmt.Errorf("error while initializing service: %w", err)
	}

	// processes incoming events from the coordinator
	upstreamDone := make(chan struct{})
	go func() {
		for ev := range upstreamChan.Incoming {
			s.Logf("new coordination event: %s", ev)
			s.processEvent(ev)     // update local state
			s.incoming <- ev.Event // pass the event downstream
		}
		close(upstreamDone)
	}()

	// process downstream outgoing events
	downstreamDone := make(chan struct{})
	go func() {
		for ev := range s.outgoing {
			s.processEvent(Event{ev})          // update local state
			upstreamChan.Outgoing <- Event{ev} // pass the event upstream
		}
		close(downstreamDone)
	}()

	<-upstreamDone
	s.Logf("upstream coordinator is done, closing downstream")
	close(s.incoming) // closing downstream

	<-executorRunReturned
	s.Logf("executor Run method returned")

	<-downstreamDone
	close(upstreamChan.Outgoing) // closing upstream
	s.Logf("downstream coordinator is done, service.Run return")

	return nil
}

func (s *Service) processEvent(ev Event) {

	if !ev.IsSetupEvent() {
		panic("non-setup event sent to setup service")
	}

	switch ev.EventType {
	case protocol.Started:
	case protocol.Completed:
		err := s.completed.CompletedProtocol(ev.Descriptor)
		if err != nil {
			panic(err)
		}
	case protocol.Failed:
	default:
		panic("unkown event type")
	}
}

// RunSignature queues the given signature for execution. This method is called by the helper.
func (s *Service) RunSignature(ctx context.Context, sig protocol.Signature) error {

	if !sig.Type.IsSetup() {
		return fmt.Errorf("signature type %s is not a setup protocol", sig.Type)
	}

	err := s.executor.RunSignature(ctx, sig, s.AggregationOutputHandler)
	if err != nil {
		panic(err)
	}

	return nil
}

// PublicKeyBackend interface implementation

// GetCollectivePublicKey returns the collective public key when available.
// The method blocks until the corresponding protocol completes.
func (s *Service) GetCollectivePublicKey(ctx context.Context) (*rlwe.PublicKey, error) {
	out, err := s.getOutputForSig(ctx, protocol.Signature{Type: protocol.CKG})
	if err != nil {
		return nil, err
	}
	return out.Result.(*rlwe.PublicKey), nil
}

// GetGaloisKey returns the Galois key for the given Galois element when available.
// The method blocks until the corresponding protocol completes.
func (s *Service) GetGaloisKey(ctx context.Context, galEl uint64) (*rlwe.GaloisKey, error) {
	out, err := s.getOutputForSig(ctx, protocol.Signature{Type: protocol.RTG, Args: map[string]string{"GalEl": fmt.Sprintf("%d", galEl)}})
	if err != nil {
		return nil, err
	}
	return out.Result.(*rlwe.GaloisKey), nil
}

// GetRelinearizationKey returns the relinearization key when available.
// The method blocks until the corresponding protocol completes.
func (s *Service) GetRelinearizationKey(ctx context.Context) (*rlwe.RelinearizationKey, error) {
	out, err := s.getOutputForSig(ctx, protocol.Signature{Type: protocol.RKG})
	if err != nil {
		return nil, err
	}
	return out.Result.(*rlwe.RelinearizationKey), nil
}

func (s *Service) getOutputForSig(ctx context.Context, sig protocol.Signature) (*protocol.Output, error) {

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

	out := protocol.AllocateOutput(sig, *sess.Params.GetRLWEParameters()) // TODO cache ?
	err = s.executor.GetOutput(ctx, *aggOut, out)
	if err != nil {
		return nil, fmt.Errorf("error while getting output: %w", err)
	}

	return &protocol.Output{Descriptor: *pd, Result: out}, nil
}

// GetProtocolInput returns the protocol inputs for the given protocol descriptor.
// It is meant to be passed to a protocols.Executor as a protocols.InputProvider method.
func (s *Service) GetProtocolInput(ctx context.Context, pd protocol.Descriptor) (protocol.Input, error) {

	sess, has := s.sessions.GetSessionFromContext(ctx)
	if !has {
		return nil, fmt.Errorf("session not found in context")
	}

	switch pd.Signature.Type {
	case protocol.CKG, protocol.RTG, protocol.RKG1:
		p, err := protocol.NewProtocol(pd, sess) // TODO: cache and reuse ?
		if err != nil {
			return nil, err
		}
		return p.ReadCRP()
	case protocol.RKG:
		aggOutR1, err := s.GetAggregationOutput(ctx, protocol.Descriptor{Signature: protocol.Signature{Type: protocol.RKG1}, Participants: pd.Participants, Aggregator: pd.Aggregator})
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
func (s *Service) GetAggregationOutput(ctx context.Context, pd protocol.Descriptor) (out *protocol.AggregationOutput, err error) {
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
		aggOutC := make(chan protocol.AggregationOutput, 1)
		err := s.executor.RunDescriptorAsAggregator(ctx, pd, func(ctx context.Context, ao protocol.AggregationOutput) error {
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

func (s *Service) getAggregationOutputFromBackend(ctx context.Context, pd protocol.Descriptor) (*protocol.AggregationOutput, error) {
	share := protocol.Share{}
	lattigoShare := pd.Signature.Type.Share()
	err := s.resBackend.GetShare(ctx, pd.Signature, lattigoShare)
	if err != nil {
		return nil, err
	}
	share.MHEShare = lattigoShare
	share.ProtocolType = pd.Signature.Type
	share.ProtocolID = pd.ID()
	return &protocol.AggregationOutput{Share: share, Descriptor: pd}, nil
}

// AggregationOutputHandler is called when a protocol aggregation completes.
// It is meant to be passed to a protocols.Executor as a protocols.AggregationOutputHandler method.
func (s *Service) AggregationOutputHandler(ctx context.Context, aggOut protocol.AggregationOutput) error {
	return s.resBackend.Put(ctx, aggOut.Descriptor, aggOut.Share)
}

// NodeID returns the node ID associated with this service.
func (s *Service) NodeID() session.NodeID {
	return s.self
}

// protocols.Coordinator interface implementation

// Incoming returns the incoming event channel for the protocols.Coordinator interface.
func (s *Service) Incoming() <-chan protocol.Event {
	return s.incoming
}

// Outgoing returns the outgoing event channel for the protocols.Coordinator interface.
func (s *Service) Outgoing() chan<- protocol.Event {
	return s.outgoing
}

// Register registers a connected node to the service.
func (s *Service) Register(nid session.NodeID) error { // TODO should be per session
	return s.executor.Register(nid)
}

// Unregister unregisters a disconnected node from the service
func (s *Service) Unregister(nid session.NodeID) error {
	return s.executor.Unregister(nid)
}

// Logf prints a log message.
func (s *Service) Logf(msg string, v ...any) {
	log.Printf("%s | [setup] %s\n", s.self, fmt.Sprintf(msg, v...))
}
