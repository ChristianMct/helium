// Package compute implements the MHE compute phase as a service.
// This service is responsible for evaluating circuits and running
// associated the protocols.
// It stats a protocol.Executor and acts as a coordinator for it.
package compute

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/ChristianMct/helium/circuit"
	"github.com/ChristianMct/helium/coordinator"
	"github.com/ChristianMct/helium/protocol"
	"github.com/ChristianMct/helium/session"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
	"github.com/tuneinsight/lattigo/v5/schemes/ckks"
	"golang.org/x/sync/errgroup"
)

func init() {
	close(NoOutput)
}

type Encoder interface {
	//Encode(any, *rlwe.Plaintext) error // TODO: Lattigo should have a more generic interface
}

// FHEProvider is an interface for requesting FHE-related objects as implemented
// in the Lattigo library.
type FHEProvider interface {
	GetParameters(ctx context.Context) (session.FHEParameters, error)
	GetEncoder(ctx context.Context) (Encoder, error)
	GetEncryptor(ctx context.Context) (*rlwe.Encryptor, error)
	// GetEvaluator(ctx context.Context, rlk bool, galEls []uint64) (*fheEvaluator, error)
	GetDecryptor(ctx context.Context) (*rlwe.Decryptor, error)
}

// CircuitRuntime is the interface of a circuit's execution environment.
// There are two notable instantiation of this interface:
//   - evaluator: the node that evaluates the circuit
//   - participant: the node that provides input to the circuit, participates in the protocols
//     and recieve outputs.
type CircuitRuntime interface {
	// Init provides the circuit runtime with the circuit's metadata.
	Init(ctx context.Context, md circuit.Metadata) (err error)

	// Eval runs the circuit evaluation, given the circuit.
	Eval(ctx context.Context, c circuit.Circuit) (err error)

	// IncomingOperand provides the circuit runtime with an incoming operand.
	IncomingOperand(circuit.Operand) error

	// CompletedProtocol informs the circuit runtime that a protocol has been completed.
	CompletedProtocol(protocol.Descriptor) error

	// GetOperand returns the operand with the given label, if it exists.
	GetOperand(context.Context, circuit.OperandLabel) (*circuit.Operand, bool)

	// GetFutureOperand returns the future operand with the given label, if it exists.
	GetFutureOperand(context.Context, circuit.OperandLabel) (*circuit.FutureOperand, bool)

	// Wait blocks until the circuit executing in this runtime (including its related protocols) completes.
	Wait() error
}

// InputProvider is a type for providing input to a circuit.
// It is generally provided by the user, and lets the framework query for
// inputs to the circuit by their label. See circuits.OperandLabel for more information on operand labels.
// Input providers are expected to return one of the following types:
// - *rlwe.Ciphertext: an encrypted input
// - *rlwe.Plaintext: a Lattigo plaintext input, which will be encrypted by the framework
// - []uint64: a Go plaintext input, which will be encoded and encrypted by the framework
type InputProvider func(context.Context, session.CircuitID, circuit.OperandLabel, session.Session) (any, error)

// NoInput is an input provider that returns nil for all inputs.
var NoInput InputProvider = func(_ context.Context, _ session.CircuitID, _ circuit.OperandLabel, _ session.Session) (any, error) {
	return nil, nil
}

// OutputReceiver is a type for receiving outputs from a circuit.
type OutputReceiver chan<- circuit.Output

// NoOutput is an output receiver that do not send any input
var NoOutput OutputReceiver = make(OutputReceiver)

// ServiceConfig is the configuration of a compute service.
type ServiceConfig struct {
	// CircQueueSize is the size of the circuit execution queue.
	// Passed this size, attempting to queue circuit for execution will block.
	CircQueueSize int
	// MaxCircuitEvaluation is the maximum number of circuits that can be evaluated concurrently.
	MaxCircuitEvaluation int
	// Protocols is the configuration of the protocol executor.
	Protocols protocol.ExecutorConfig
}

type Event struct {
	CircuitEvent  *circuit.Event
	ProtocolEvent *protocol.Event
}

type Coordinator coordinator.Coordinator[Event]

// Service represents a compute service instance.
type Service struct {
	config ServiceConfig
	self   session.NodeID

	sessions session.SessionProvider
	*protocol.Executor
	transport Transport

	pubkeyBackend circuit.PublicKeyProvider

	inputProvider InputProvider
	localOutputs  chan circuit.Output

	outputsMu sync.RWMutex
	outputs   map[circuit.OperandLabel]*circuit.Operand

	queuedCircuits chan circuit.Descriptor

	runningCircuitsMu sync.RWMutex
	runningCircuits   map[session.CircuitID]CircuitRuntime

	completedCircuits chan circuit.Descriptor

	// upstream coordinator

	// downstream coordinator
	incoming, outgoing chan protocol.Event

	// circuit library
	library map[circuit.Name]circuit.Circuit
}

const (
	// DefaultCircQueueSize is the default size of the circuit execution queue.
	DefaultCircQueueSize = 512
	// DefaultMaxCircuitEvaluation is the default maximum number of circuits that can be evaluated concurrently.
	DefaultMaxCircuitEvaluation = 10
)

// NewComputeService creates a new compute service instance.
func NewComputeService(ownID session.NodeID, sessions session.SessionProvider, conf ServiceConfig, pkbk circuit.PublicKeyProvider) (s *Service, err error) {
	s = new(Service)

	s.config = conf
	if s.config.CircQueueSize == 0 {
		s.config.CircQueueSize = DefaultCircQueueSize
	}
	if s.config.MaxCircuitEvaluation == 0 {
		s.config.MaxCircuitEvaluation = DefaultMaxCircuitEvaluation
	}

	// coordinator
	s.incoming = make(chan protocol.Event)
	s.outgoing = make(chan protocol.Event)

	s.self = ownID
	s.sessions = sessions
	s.Executor, err = protocol.NewExectutor(conf.Protocols, s.self, sessions, &coordinator.Channel[protocol.Event]{Incoming: s.incoming, Outgoing: s.outgoing}, s.GetProtocolInput)
	if err != nil {
		return nil, err
	}

	s.pubkeyBackend = session.NewCachedPublicKeyBackend(pkbk)

	s.queuedCircuits = make(chan circuit.Descriptor, conf.CircQueueSize)

	s.runningCircuits = make(map[session.CircuitID]CircuitRuntime)

	//s.running = make(chan struct{})

	s.localOutputs = make(chan circuit.Output)
	s.outputs = make(map[circuit.OperandLabel]*circuit.Operand)

	return s, nil
}

// RegisterCircuit registers a circuit to the service's library.
// It returns an error if the circuit is already registered.
func (s *Service) RegisterCircuit(name circuit.Name, circ circuit.Circuit) error {
	if s.library == nil {
		s.library = make(map[circuit.Name]circuit.Circuit)
	}
	if _, has := s.library[name]; has {
		return fmt.Errorf("circuit name \"%s\" already registered", name)
	}
	s.library[name] = circ
	return nil
}

// RegisterCircuits registers a set of circuits to the service's library.
// It returns an error if any of the circuits is already registered.
func (s *Service) RegisterCircuits(cs map[circuit.Name]circuit.Circuit) error {
	for cn, c := range cs {
		if err := s.RegisterCircuit(cn, c); err != nil {
			return err
		}
	}
	return nil
}

func recoverPresentState(events <-chan Event, present int) (completedProto, failedProto, runningProto []protocol.Descriptor, completedCirc, failedCirc, runningCirc []circuit.Descriptor, err error) {

	if present == 0 {
		return
	}

	var current int
	runProto := make(map[protocol.ID]protocol.Descriptor)
	runCircuit := make(map[session.CircuitID]circuit.Descriptor)
	for ev := range events {

		if ev.CircuitEvent != nil {
			cid := ev.CircuitEvent.CircuitID
			switch ev.CircuitEvent.EventType {
			case circuit.Started:
				runCircuit[cid] = ev.CircuitEvent.Descriptor
			case circuit.Executing:
				if _, has := runCircuit[cid]; !has {
					err = fmt.Errorf("inconsisted state, circuit %s execution event before start", cid)
					return
				}
			case circuit.Completed, circuit.Failed:
				if _, has := runCircuit[cid]; !has {
					err = fmt.Errorf("inconsisted state, circuit %s termination event before start", cid)
					return
				}
				delete(runCircuit, cid)
				if ev.CircuitEvent.EventType == circuit.Completed {
					completedCirc = append(completedCirc, ev.CircuitEvent.Descriptor)
				} else {
					failedCirc = append(failedCirc, ev.CircuitEvent.Descriptor)
				}
			}
		}

		if ev.ProtocolEvent != nil {
			pid := ev.ProtocolEvent.ID()
			switch ev.ProtocolEvent.EventType {
			case protocol.Started:
				runProto[pid] = ev.ProtocolEvent.Descriptor
			case protocol.Executing:
				if _, has := runProto[pid]; !has {
					err = fmt.Errorf("inconsisted state, protocol %s execution event before start", ev.ProtocolEvent.HID())
					return
				}
			case protocol.Completed, protocol.Failed:
				if _, has := runProto[pid]; !has {
					err = fmt.Errorf("inconsisted state, protocol %s termination event before start", ev.ProtocolEvent.HID())
					return
				}
				delete(runProto, pid)
				if ev.ProtocolEvent.EventType == protocol.Completed {
					completedProto = append(completedProto, ev.ProtocolEvent.Descriptor)
				} else {
					failedProto = append(failedProto, ev.ProtocolEvent.Descriptor)
				}
			}
		}

		current++
		if current == present {
			break
		}
	}

	for _, rp := range runProto {
		runningProto = append(runningProto, rp)
	}

	for _, rc := range runCircuit {
		runningCirc = append(runningCirc, rc)
	}

	return
}

// Init initializes the compute service with the currently completed and running circuits and protocols.
// It queues running circuits and protocols for execution.
func (s *Service) init(ctx context.Context, upstreamInc <-chan Event, present int) error { // TODO make private

	complPd, failPd, runPd, complCd, failCd, runCd, err := recoverPresentState(upstreamInc, present)
	if err != nil {
		return err
	}

	// stacks the completed circuit in a queue for processing by Run
	s.completedCircuits = make(chan circuit.Descriptor, len(complCd))
	for _, ccd := range complCd {
		s.completedCircuits <- ccd
	}

	// create and queues the running circuits
	for _, rcd := range runCd {
		if err := s.createCircuit(ctx, rcd); err != nil {
			return err
		}
		s.queuedCircuits <- rcd
	}

	// sends the completed
	for _, cpd := range complPd {

		if !cpd.Signature.Type.IsCompute() {
			continue
		}

		if err := s.sendCompletedPdToCircuit(cpd); err != nil {
			return err
		}
	}

	// sends the running pd to the protocol executor
	for _, rpd := range runPd {
		if !rpd.Signature.Type.IsCompute() {
			continue
		}
		s.incoming <- protocol.Event{EventType: protocol.Started, Descriptor: rpd}
	}

	s.Logf("service initialized protocols with %d completed, %d failed and %d running (present=%d)", len(complPd), len(failPd), len(runPd), present)
	s.Logf("service initialized circuits with %d completed, %d failed and %d running (present=%d)", len(complCd), len(failCd), len(runCd), present)

	return nil
}

// Run runs the compute service. The service processes incoming events from the upstream coordinator and acts as a
// coordinator for the protocol executor. It also processes the circuit execution queue and fetches the output for
// completed circuits.
// The method returns when the upstream coordinator is done and all circuits are completed.
func (s *Service) Run(ctx context.Context, ip InputProvider, or OutputReceiver, upstream Coordinator, trans Transport) error {

	s.Logf("starting service.Run")

	s.transport = trans
	s.inputProvider = ip

	runCtx, cancelRunCtx := context.WithCancel(session.ContextWithNodeID(ctx, s.self))
	defer cancelRunCtx()

	// registers to the upstream coordinator
	upstreamChan, present, err := upstream.Register(runCtx)
	if err != nil {
		return fmt.Errorf("error registering to upstream coordinator: %w", err)
	}

	// starts the protocol executor (init sends running protocols to its queue)
	go func() {
		if err := s.Executor.Run(ctx, s.transport); err != nil {
			panic(err) // TODO: return in Run
		}
	}()

	// fetches the output for completed circuits (peer nodes only, init sends compl circuit to this queue)
	go func() {
		if or != nil {
			for cd := range s.completedCircuits {
				c, has := s.library[cd.Name]
				if !has {
					panic(fmt.Errorf("no registered circuit for name \"%s\"", cd.Name))
				}

				sess, has := s.sessions.GetSessionFromContext(ctx)
				if !has {
					panic(fmt.Errorf("could not retrieve session from the context"))
				}

				params := sess.Params

				cinf, err := circuit.Parse(c, cd, params)
				if err != nil {
					panic(err)
				}

				for opl := range cinf.OutputsFor[s.self] {
					ct, err := s.transport.GetCiphertext(ctx, session.CiphertextID(opl))
					if err != nil {
						panic(err)
					}

					or <- circuit.Output{CircuitID: cd.CircuitID, Operand: circuit.Operand{OperandLabel: opl, Ciphertext: &ct.Ciphertext}}
				}
			}
		} else {
			for range s.completedCircuits {
			}
		}
	}()

	// processes the circuit execution queue (init sends running circuits to this queue)
	evalRoutines, erctx := errgroup.WithContext(ctx)
	for i := 0; i < s.config.MaxCircuitEvaluation; i++ {
		evalRoutines.Go(func() error {
			for cd := range s.queuedCircuits {
				if err := s.runCircuit(erctx, cd, *upstreamChan); err != nil {
					s.Logf("error during circuit execution %s: %v", cd.CircuitID, err)
					return err
				}
			}
			return nil
		})
	}

	// initializes the service from the current state of the protocols
	if err = s.init(runCtx, upstreamChan.Incoming, present); err != nil {
		return fmt.Errorf("error while initializing service: %w", err)
	}

	// process incoming upstream Events
	go func() {
		for ev := range upstreamChan.Incoming {

			if ev.ProtocolEvent != nil {
				pev := *ev.ProtocolEvent

				s.Logf("new coordination event: PROTOCOL %s", pev)

				s.incoming <- pev

				switch pev.EventType {
				case protocol.Completed:
					if err := s.sendCompletedPdToCircuit(pev.Descriptor); err != nil {
						panic(err)
					}
				}

				continue
			}

			cev := *ev.CircuitEvent
			s.Logf("new coordination event: CIRCUIT %s", cev)
			switch ev.CircuitEvent.EventType {
			case circuit.Started:
				err := s.createCircuit(ctx, cev.Descriptor)
				if err != nil {
					panic(err)
				}
				s.queuedCircuits <- cev.Descriptor
			case circuit.Completed, circuit.Failed:
				s.runningCircuitsMu.Lock()
				delete(s.runningCircuits, ev.CircuitEvent.CircuitID)
				s.runningCircuitsMu.Unlock()
			}
		}
		s.Logf("upstream coordinator done")
		close(s.queuedCircuits)
	}()

	// process downstream incoming coordination events
	downstreamDone := make(chan struct{})
	go func() {
		for pev := range s.outgoing {
			pev := pev
			upstreamChan.Outgoing <- Event{ProtocolEvent: &pev}

			if pev.EventType == protocol.Completed {
				opls, has := pev.Signature.Args["op"]
				if !has {
					panic("no op argument in circuit protocol event")
				}

				opl := circuit.OperandLabel(opls)
				cid := opl.CircuitID()

				s.runningCircuitsMu.RLock()
				c, has := s.runningCircuits[cid]
				if !has {
					panic(fmt.Errorf("circuit with id %s is not running", cid))
				}
				s.runningCircuitsMu.RUnlock()

				c.CompletedProtocol(pev.Descriptor)
			}

		}
		close(downstreamDone)
	}()

	// sends the local outputs to the output receiver if any
	go func() {
		if or != nil {
			for lop := range s.localOutputs {
				or <- lop
			}
			close(or)
		} else {
			for range s.localOutputs {
			}
		}
	}()

	err = evalRoutines.Wait()
	if err != nil {
		return err
	}
	s.Logf("all circuits done")

	close(s.incoming) // closing downstream coordinator
	<-downstreamDone  // waiting for downstream to close its outgoing channel

	s.Logf("downstream coordinator done, Run returns")
	close(upstreamChan.Outgoing) // close own outgoing channel
	close(s.localOutputs)
	return nil
}

func (s *Service) sendCompletedPdToCircuit(pd protocol.Descriptor) error {
	opls, has := pd.Signature.Args["op"]
	if !has {
		panic("no op argument in circuit protocol event")
	}

	opl := circuit.OperandLabel(opls)
	cid := opl.CircuitID()

	s.runningCircuitsMu.RLock()
	c, has := s.runningCircuits[cid]
	s.runningCircuitsMu.RUnlock()
	if !has {
		panic(fmt.Errorf("circuit is not runnig: %s", cid))
	}

	return c.CompletedProtocol(pd)
}

// validateCircuitDescriptor checks that a circuit descriptor is valid and can be executed by
// the service.
func (s *Service) validateCircuitDescriptor(cd circuit.Descriptor) error {
	if len(cd.CircuitID) == 0 {
		return fmt.Errorf("circuit descriptor has no id")
	}
	if len(cd.Name) == 0 {
		return fmt.Errorf("circuit descriptor has no name")
	}
	if len(cd.NodeMapping) == 0 {
		return fmt.Errorf("circuit descriptor has no node mapping")
	}
	if len(cd.Evaluator) == 0 {
		return fmt.Errorf("circuit descriptor has no evaluator")
	}
	// TODO: further checks
	return nil
}

func (s *Service) createCircuit(ctx context.Context, cd circuit.Descriptor) (err error) {
	var cr CircuitRuntime
	sess, has := s.sessions.GetSessionFromContext(ctx) // put session unwrap earlier
	if !has {
		return fmt.Errorf("session not found from context")
	}

	if err := s.validateCircuitDescriptor(cd); err != nil {
		return fmt.Errorf("invalid circuit descriptor: %w", err)
	}

	if s.isEvaluator(cd) {
		cr = &evaluatorRuntime{
			ctx:         ctx,
			cDesc:       cd,
			sess:        sess,
			pkProvider:  s.pubkeyBackend,
			protoExec:   s,
			fheProvider: s,
		}
	} else {
		cr = &participantRuntime{
			ctx:           ctx,
			cd:            cd,
			sess:          sess,
			inputProvider: s.inputProvider,
			or:            s.localOutputs,
			trans:         s.transport,
			fheProvider:   s,
			incpd:         make(chan protocol.Descriptor, 100), // TODO: not ideal
		}

	}
	s.runningCircuitsMu.Lock()
	_, has = s.runningCircuits[cd.CircuitID]
	if has {
		s.runningCircuitsMu.Unlock()
		return fmt.Errorf("circuit with id %s is already runnning", cd.CircuitID)
	}
	s.runningCircuits[cd.CircuitID] = cr
	s.runningCircuitsMu.Unlock()

	s.Logf("created circuit %s", cd.CircuitID)
	return
}

func (s *Service) runCircuit(ctx context.Context, cd circuit.Descriptor, upstreamChan coordinator.Channel[Event]) (err error) {

	s.runningCircuitsMu.RLock()
	cinst, has := s.runningCircuits[cd.CircuitID]
	s.runningCircuitsMu.RUnlock()
	if !has {
		return fmt.Errorf("circuit %s was not created", cd.CircuitID)
	}

	c, has := s.library[cd.Name]
	if !has {
		return fmt.Errorf("no registered circuit for name \"%s\"", cd.Name)
	}

	sess, has := s.sessions.GetSessionFromContext(ctx)
	if !has {
		return fmt.Errorf("could not retrieve session from the context")
	}

	params := sess.Params

	cinf, err := circuit.Parse(c, cd, params)
	if err != nil {
		return err
	}

	err = cinst.Init(ctx, *cinf)
	if err != nil {
		return fmt.Errorf("error at circuit initialization: %w", err)
	}
	//<-s.running // waits for the Run function to be called

	if s.isEvaluator(cd) {
		err = s.runCircuitAsEvaluator(ctx, c, cinst, *cinf, upstreamChan)
	} else {
		err = s.runCircuitAsParticipant(ctx, c, cinst, *cinf)
	}

	return err
}

func (s *Service) runCircuitAsEvaluator(ctx context.Context, c circuit.Circuit, ev CircuitRuntime, md circuit.Metadata, upstreamChan coordinator.Channel[Event]) (err error) {
	cd := md.Descriptor
	s.Logf("started circuit %s as evaluator", cd.CircuitID)

	upstreamChan.Outgoing <- Event{CircuitEvent: &circuit.Event{EventType: circuit.Started, Descriptor: cd}}

	err = ev.Eval(ctx, c)
	if err != nil {
		return fmt.Errorf("error at circuit evaluation: %w", err)
	}

	for outLabel := range md.OutputSet {
		op, has := ev.GetOperand(ctx, outLabel)
		if !has {
			panic(fmt.Errorf("circuit should have output operand %s", outLabel))
		}
		s.outputsMu.Lock()
		s.outputs[outLabel] = op
		s.outputsMu.Unlock()
	}

	for outLabel := range md.OutputsFor[s.self] {
		fop, has := ev.GetOperand(ctx, outLabel)
		if !has {
			panic(fmt.Errorf("circuit instance has no output label %s", outLabel))
		}
		s.localOutputs <- circuit.Output{CircuitID: cd.CircuitID, Operand: *fop}
	}

	upstreamChan.Outgoing <- Event{CircuitEvent: &circuit.Event{EventType: circuit.Completed, Descriptor: cd}}

	s.runningCircuitsMu.Lock()
	delete(s.runningCircuits, cd.CircuitID)
	nRunning := len(s.runningCircuits)
	s.runningCircuitsMu.Unlock()

	s.Logf("completed circuit %s as evaluator, %d running", cd.CircuitID, nRunning)

	return nil
}

func (s *Service) runCircuitAsParticipant(ctx context.Context, c circuit.Circuit, part CircuitRuntime, md circuit.Metadata) error {

	s.Logf("started circuit %s as participant, has input: %v, has output: %v", md.Descriptor.CircuitID, s.isInputProvider(md), s.isOutputReceiver(md))

	err := part.Eval(ctx, c)
	if err != nil {
		return err
	}

	//s.runningCircuitWg.Done() // TODO: get the circuit complete message in this function to so that all runningcircuit management takes place here
	s.Logf("completed circuit %s as participant", md.Descriptor.CircuitID)

	return nil
}

func (s *Service) EvalCircuit(ctx context.Context, cd circuit.Descriptor) error {
	err := s.createCircuit(ctx, cd)
	if err != nil {
		return err
	}
	s.queuedCircuits <- cd
	return nil
}

// KeyOperationRunner interface

// RunKeyOperation runs a key operation (e.g. key switching) on the service's executor.
func (s *Service) RunKeyOperation(ctx context.Context, sig protocol.Signature) (err error) {
	err = s.Executor.RunSignature(ctx, sig, s.AggregationOutputHandler)
	return err
}

// Transport interface

// GetCiphertext retreives a ciphertext from the corresponding circuit runtime.
// The runtime is identified by the circuit ID part of the ciphertext ids.
func (s *Service) GetCiphertext(ctx context.Context, ctID session.CiphertextID) (*session.Ciphertext, error) {

	_, exists := s.sessions.GetSessionFromContext(ctx)
	if !exists {
		return nil, fmt.Errorf("invalid session id")
	}

	ctURL, err := ParseURL(string(ctID))
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext id format")
	}

	if ctURL.NodeID() != "" && ctURL.NodeID() != s.self {
		return nil, fmt.Errorf("non-local ciphertext id")
	}

	cid := session.CircuitID(ctURL.CircuitID())
	if len(cid) == 0 {
		return nil, fmt.Errorf("ciphertext label does not include a circuit ID")
	}

	var ct *session.Ciphertext
	var op *circuit.Operand
	var isOutput, isInCircuit bool
	s.outputsMu.RLock()
	op, isOutput = s.outputs[circuit.OperandLabel(ctID)]
	s.outputsMu.RUnlock()
	if !isOutput {
		s.runningCircuitsMu.RLock()
		evalCtx, envExists := s.runningCircuits[cid]
		s.runningCircuitsMu.RUnlock()
		if !envExists {
			return nil, fmt.Errorf("%s is not an output and circuit %s is not running", ctID, ctURL.CircuitID())
		}
		op, isInCircuit = evalCtx.GetOperand(ctx, circuit.OperandLabel(ctURL.String()))
	}

	if !isOutput && !isInCircuit {
		return nil, fmt.Errorf("ciphertext with id %s not found for circuit %s", ctID, ctURL.CircuitID())
	}

	ct = &session.Ciphertext{Ciphertext: *op.Ciphertext}
	return ct, nil
}

// PutCiphertext provides the ciphertext to the corresponding circuit runtime.
// The runtime is identified by the circuit ID part of the ciphertext ids.
func (s *Service) PutCiphertext(ctx context.Context, ct session.Ciphertext) error {

	_, exists := s.sessions.GetSessionFromContext(ctx)
	if !exists {
		sessid, _ := session.IDFromContext(ctx)
		return fmt.Errorf("invalid session id \"%s\"", sessid)
	}

	ctURL, err := ParseURL(string(ct.ID))
	if err != nil {
		return fmt.Errorf("invalid ciphertext id \"%s\": %w", ct.ID, err)
	}

	cid := session.CircuitID(ctURL.CircuitID())

	if len(cid) == 0 {
		return fmt.Errorf("ciphertext label does not include a circuit ID")
	}

	s.runningCircuitsMu.RLock()
	c, envExists := s.runningCircuits[cid]
	s.runningCircuitsMu.RUnlock()
	if !envExists {
		return fmt.Errorf("for unknown circuit %s", cid)
	}

	op := circuit.Operand{OperandLabel: circuit.OperandLabel(ct.ID), Ciphertext: &ct.Ciphertext}
	err = c.IncomingOperand(op)
	if err != nil {
		return err
	}

	s.Logf("recieved ciphertext for operand %s", op.OperandLabel)

	return nil
}

// AggregationOutputHandler recieves the completed protocol aggregations from the executor.
func (s *Service) AggregationOutputHandler(ctx context.Context, aggOut protocol.AggregationOutput) error {
	c, err := s.getCircuitFromContext(ctx)
	if err != nil {
		return err
	}

	sess, has := s.sessions.GetSessionFromContext(ctx)
	if !has {
		return fmt.Errorf("no session found for this context")
	}

	inOpl, has := aggOut.Descriptor.Signature.Args["op"]
	if !has {
		return fmt.Errorf("invalid aggregation output: descriptor does not provide input operand label")
	}

	outOpl := keyOpOutputLabel(circuit.OperandLabel(inOpl), aggOut.Descriptor.Signature)

	fop, has := c.GetFutureOperand(ctx, outOpl)
	if !has {
		return fmt.Errorf("invalid aggregation output: unkown output operand: %s", outOpl)
	}

	out := protocol.AllocateOutput(aggOut.Descriptor.Signature, *sess.Params.GetRLWEParameters())
	err = s.Executor.GetOutput(ctx, aggOut, out)
	if err != nil {
		return fmt.Errorf("protocol output resulted in an error: %w", err)
	}

	outCt := out.(*rlwe.Ciphertext)

	fop.Set(circuit.Operand{OperandLabel: outOpl, Ciphertext: outCt})

	return nil

}

// GetProtocolInput returns the input for a protocol from the corresponding circuit runtime.
// The input is the ciphertext identified by the "op" protocol argument.
// The runtime is identified by the circuit ID part of the operand label.
func (s *Service) GetProtocolInput(ctx context.Context, pd protocol.Descriptor) (in protocol.Input, err error) {

	opl, has := pd.Signature.Args["op"]
	if !has {
		return nil, fmt.Errorf("invalid protocol descriptor: no operand specified")
	}

	c, err := s.getCircuitFromOperandLabel(circuit.OperandLabel(opl))
	if err != nil {
		return nil, err
	}

	op, has := c.GetOperand(ctx, circuit.OperandLabel(opl))
	if !has {
		return nil, fmt.Errorf("invalid protocol descriptor: operand label %s not in circuit", opl)
	}

	sess, has := s.sessions.GetSessionFromContext(ctx)
	if !has {
		return nil, fmt.Errorf("no session found for this context")
	}

	ksin := &protocol.KeySwitchInput{InpuCt: op.Ciphertext}
	switch pd.Signature.Type {
	case protocol.DEC:
		ksin.OutputKey = rlwe.NewSecretKey(sess.Params) // TODO put in session
	case protocol.CKS, protocol.PCKS:
		return nil, fmt.Errorf("key switch protocol not supported yet") // TODO
	default:
		return nil, fmt.Errorf("invalid protocol type: %s", pd.Signature.Type)
	}
	return ksin, nil

}

// protocols.Coordinator interface

// Incoming returns the incoming event channel.
func (s *Service) Incoming() <-chan protocol.Event {
	return s.incoming
}

// Outgoing returns the outgoing event channel.
func (s *Service) Outgoing() chan<- protocol.Event {
	return s.outgoing
}

// FHEProvider interface

// GetParameters returns the parameters of the context's session.
func (s *Service) GetParameters(ctx context.Context) (session.FHEParameters, error) {
	if sess, has := s.sessions.GetSessionFromContext(ctx); has {
		return sess.Params, nil
	}
	return nil, fmt.Errorf("no session found for context")
}

// GetEncoder returns a new encoder from the context's session.
func (s *Service) GetEncoder(ctx context.Context) (enc Encoder, err error) {

	sess, has := s.sessions.GetSessionFromContext(ctx)
	if !has {
		return nil, fmt.Errorf("no session found for this context")
	}

	switch p := sess.Params.(type) {
	case bgv.Parameters:
		enc = bgv.NewEncoder(p)
	case ckks.Parameters:
		enc = ckks.NewEncoder(p)
	default:
		return nil, fmt.Errorf("session has unsupported parameters type: %T", p)
	}

	return enc, nil
}

// GetEncryptor returns a new encryptor from the context's session and the collective public key.
func (s *Service) GetEncryptor(ctx context.Context) (*rlwe.Encryptor, error) {

	sess, has := s.sessions.GetSessionFromContext(ctx)
	if !has {
		return nil, fmt.Errorf("no session found for this context")
	}

	cpk, err := s.pubkeyBackend.GetCollectivePublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot retrieve the collective public key : %w", err)
	}

	return rlwe.NewEncryptor(sess.Params, cpk), nil
}

// // GetEvaluator returns a new evaluator from the context's session and relevant evaluation keys.
// func (s *Service) GetEvaluator(ctx context.Context, relin bool, galEls []uint64) (*fheEvaluator, error) {
// 	sess, has := s.sessions.GetSessionFromContext(ctx)
// 	if !has {
// 		return nil, fmt.Errorf("no session found for this context")
// 	}

// 	return newLattigoEvaluator(ctx, relin, galEls, sess.Params, s.pubkeyBackend)
// }

// GetDecryptor returns a new decryptor from the context's session.
// The decryptor is inialized with a secret key of 0.
func (s *Service) GetDecryptor(ctx context.Context) (*rlwe.Decryptor, error) {
	sess, has := s.sessions.GetSessionFromContext(ctx)
	if !has {
		return nil, fmt.Errorf("no session found for this context")
	}

	return rlwe.NewDecryptor(sess.Params, rlwe.NewSecretKey(sess.Params)), nil // decryptor under sk=0 (sk is determined at output)

}

func (s *Service) getCircuitFromContext(ctx context.Context) (CircuitRuntime, error) {
	cid, has := session.CircuitIDFromContext(ctx)
	if !has {
		return nil, fmt.Errorf("should have circuit id in context")
	}

	s.runningCircuitsMu.RLock()
	c, envExists := s.runningCircuits[session.CircuitID(cid)]
	s.runningCircuitsMu.RUnlock()
	if !envExists {
		return nil, fmt.Errorf("unknown circuit %s", cid)
	}

	return c, nil
}

func (s *Service) getCircuitFromOperandLabel(opl circuit.OperandLabel) (CircuitRuntime, error) {

	cid := opl.CircuitID()

	s.runningCircuitsMu.RLock()
	c, envExists := s.runningCircuits[session.CircuitID(cid)]
	s.runningCircuitsMu.RUnlock()
	if !envExists {
		return nil, fmt.Errorf("unknown circuit %s", cid)
	}
	return c, nil
}

func (s *Service) isInputProvider(md circuit.Metadata) bool {
	return len(md.InputsFor[s.self]) > 0
}

func (s *Service) isOutputReceiver(md circuit.Metadata) bool {
	return len(md.OutputsFor[s.self]) > 0
}

func (s *Service) isEvaluator(cd circuit.Descriptor) bool {
	return cd.Evaluator == s.self
}

func (s *Service) Logf(msg string, v ...any) {
	log.Printf("%s | [compute] %s\n", s.self, fmt.Sprintf(msg, v...))
}
