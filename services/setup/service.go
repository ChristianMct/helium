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
	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/services"
	"github.com/ChristianMct/helium/sessions"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
)

// ServiceConfig is the configuration for the setup service.
type ServiceConfig struct {
	Protocols protocols.ExecutorConfig
}

// Service represents an instance of the setup service.
type Service struct {
	self sessions.NodeID

	sessProv sessions.Provider

	executor  *protocols.Executor
	transport Transport

	// protocols.Coordinator
	incoming, outgoing chan protocols.Event

	resBackend *objStoreResultBackend

	//l         sync.RWMutex
	completed *protocols.CompleteMap
}

type Event struct {
	protocols.Event
}

type Coordinator coordinator.Coordinator[Event]

// NewSetupService creates a new setup service.
func NewSetupService(ownID sessions.NodeID, sessProv sessions.Provider, conf ServiceConfig, backend objectstore.ObjectStore) (s *Service, err error) {
	s = new(Service)

	s.self = ownID
	s.sessProv = sessProv

	s.incoming = make(chan protocols.Event)
	s.outgoing = make(chan protocols.Event)

	s.executor, err = protocols.NewExectutor(conf.Protocols, s.self, sessProv, &coordinator.Channel[protocols.Event]{Incoming: s.incoming, Outgoing: s.outgoing}, s.GetProtocolInput)
	if err != nil {
		return nil, err
	}

	s.resBackend = newObjStoreResultBackend(backend)
	return s, nil
}

func recoverPresentState(events <-chan Event, present int) (completePd, failPd, runningPd []protocols.Descriptor, err error) {

	if present == 0 {
		return
	}

	var current int
	runProto := make(map[protocols.ID]protocols.Descriptor)
	for ev := range events {
		pid := ev.ID()
		if !ev.Signature.Type.IsSetup() {
			return nil, nil, nil, fmt.Errorf("non-setup event %s", ev.HID())
		}

		switch ev.EventType {
		case protocols.Started:
			runProto[pid] = ev.Descriptor
		case protocols.Executing:
			if _, has := runProto[pid]; !has {
				err = fmt.Errorf("inconsisted state, protocol %s execution event before start", ev.HID())
				return
			}
		case protocols.Completed, protocols.Failed:
			if _, has := runProto[pid]; !has {
				err = fmt.Errorf("inconsisted state, protocol %s termination event before start", ev.HID())
				return
			}
			delete(runProto, pid)
			if ev.EventType == protocols.Completed {
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
// Returns true if the setup is done.
func (s *Service) init(upstreamInc <-chan Event, present int) (bool, error) {

	var complPd, failPd, runPd, err = recoverPresentState(upstreamInc, present)
	if err != nil {
		return false, err
	}

	// mark completed protocols
	for _, cpd := range complPd {
		if err := s.completed.CompletedProtocol(cpd); err != nil {
			return false, err
		}
	}
	setupDone := s.completed.IsComplete()

	// queue running protocols
	for _, rpd := range runPd {
		s.incoming <- protocols.Event{EventType: protocols.Started, Descriptor: rpd} // sends a protocol started event downstream
	}

	s.Logf("service initialized with %d completed, %d failed and %d running protocols (present=%d, setupDone=%v)", len(complPd), len(failPd), len(runPd), present, setupDone)

	return setupDone, nil
}

// Run runs the setup service as coordinated by the given coordinator.
// It processes and forwards incoming events from upstream (coordinator) and downstream (executor).
// It returns when the upstream coordinator is done and the downstream executor is done.
func (s *Service) Run(ctx context.Context, upstream Coordinator, trans Transport, desc Description) error {

	s.Logf("starting service.Run")

	s.transport = trans

	sigList := DescriptionToSignatureList(desc)
	if desc.Rlk {
		sigList = append(sigList, protocols.Signature{Type: protocols.RKG1})
	}

	s.completed = protocols.NewCompletedProt(sigList)

	runCtx, cancelRunCtx := context.WithCancel(context.WithValue(sessions.ContextWithNodeID(ctx, s.self), services.CtxKeyName, "setup"))
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

	upstreamOrSetupDone := make(chan struct{})

	// initializes the service from the current state of the protocols
	setupDone, err := s.init(upstreamChan.Incoming, present)
	if err != nil {
		return fmt.Errorf("error while initializing service: %w", err)
	}
	if setupDone {
		close(upstreamOrSetupDone)
	} else {
		// processes incoming events from the coordinator
		go func() {
			for ev := range upstreamChan.Incoming {
				s.Logf("new coordination event: %s", ev)
				setupDone := s.processEvent(ev) // update local state
				if setupDone {
					s.Logf("setup is done")
					break
				}
				s.incoming <- ev.Event // pass the event downstream
			}
			close(upstreamOrSetupDone)
		}()
	}

	// process downstream outgoing events
	downstreamDone := make(chan struct{})
	go func() {
		for ev := range s.outgoing {
			s.processEvent(Event{ev})          // update local state
			upstreamChan.Outgoing <- Event{ev} // pass the event upstream
		}
		close(downstreamDone)
	}()

	<-upstreamOrSetupDone
	s.Logf("upstream coordinator or setup is done, closing downstream")
	close(s.incoming) // closing downstream

	<-executorRunReturned
	s.Logf("executor Run method returned")

	<-downstreamDone
	close(upstreamChan.Outgoing) // closing upstream
	s.Logf("downstream coordinator is done, service.Run return")

	return nil
}

func (s *Service) processEvent(ev Event) (setupDone bool) {

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

	return s.completed.IsComplete()
}

// RunSignature queues the given signature for execution. This method is called by the helper.
func (s *Service) RunSignature(ctx context.Context, sig protocols.Signature) error {

	if !sig.Type.IsSetup() {
		return fmt.Errorf("signature type %s is not a setup protocol", sig.Type)
	}

	err := s.executor.RunSignature(ctx, sig, s.AggregationOutputHandler)
	if err != nil {
		panic(err)
	}

	return nil
}

func (s *Service) GetCompletedDescriptor(ctx context.Context, sig protocols.Signature) (*protocols.Descriptor, error) {
	return s.resBackend.GetProtocolDesc(ctx, sig)
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

	sess, has := s.sessProv.GetSessionFromContext(ctx)
	if !has {
		return nil, sessions.ErrIDNotFoundInContext
	}

	out := protocols.AllocateOutput(sig, *sess.Params.GetRLWEParameters()) // TODO cache ?
	err = s.executor.GetOutput(ctx, *aggOut, out)
	if err != nil {
		return nil, fmt.Errorf("error while getting output: %w", err)
	}

	return &protocols.Output{Descriptor: *pd, Result: out}, nil
}

// GetProtocolInput returns the protocol inputs for the given protocol descriptor.
// It is meant to be passed to a protocols.Executor as a protocols.InputProvider method.
func (s *Service) GetProtocolInput(ctx context.Context, pd protocols.Descriptor) (protocols.Input, error) {

	sess, has := s.sessProv.GetSessionFromContext(ctx)
	if !has {
		return nil, sessions.ErrIDNotFoundInContext
	}

	switch pd.Signature.Type {
	case protocols.CKG, protocols.RTG, protocols.RKG1:
		p, err := protocols.NewProtocol(pd, sess) // TODO: cache and reuse ?
		if err != nil {
			return nil, err
		}
		return p.ReadCRP()
	case protocols.RKG:
		aggOutR1, err := s.GetAggregationOutput(ctx, protocols.Descriptor{Signature: protocols.Signature{Type: protocols.RKG1}, Participants: pd.Participants, Aggregator: pd.Aggregator})
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
	// first checks if it has the share locally and if so returns it
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
		out, err = s.executor.RunDescriptorAsAggregator(ctx, pd)
		if err != nil {
			return nil, err
		}
		if out.Error != nil {
			return nil, fmt.Errorf("aggregation error for %s: %w", pd.HID(), out.Error)
		}
	}

	// store the output in the result backend
	if err := s.resBackend.Put(ctx, pd, out.Share); err != nil {
		return out, fmt.Errorf("error when storing aggregation output: %w", err)
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
func (s *Service) NodeID() sessions.NodeID {
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
func (s *Service) Register(nid sessions.NodeID) error { // TODO should be per session
	return s.executor.Register(nid)
}

// Unregister unregisters a disconnected node from the service
func (s *Service) Unregister(nid sessions.NodeID) error {
	return s.executor.Unregister(nid)
}

// Logf prints a log message.
func (s *Service) Logf(msg string, v ...any) {
	log.Printf("%s | [setup] %s\n", s.self, fmt.Sprintf(msg, v...))
}
