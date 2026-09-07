// Package compute implements the MHE compute phase as a service.
// This service is responsible for evaluating circuits and running
// the associated key-switching protocols through a protocols.MHEMPC engine.
package compute

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/ChristianMct/helium/circuits"
	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/services"
	"github.com/ChristianMct/helium/sessions"
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
	GetParameters(ctx context.Context) (sessions.FHEParameters, error)
	GetEncoder(ctx context.Context) (Encoder, error)
	GetEncryptor(ctx context.Context) (*rlwe.Encryptor, error)
	GetDecryptor(ctx context.Context) (*rlwe.Decryptor, error)
}

type OperandProvider interface {
	GetOperand(circuits.OperandLabel) (*circuits.Operand, bool)
	PutOperand(circuits.OperandLabel, *circuits.Operand) error
}

// CircuitRuntime is the interface of a circuit's execution environment.
// There are two notable instantiation of this interface:
//   - evaluator: the node that evaluates the circuit
//   - participant: the node that provides input to the circuit, participates in the protocols
//     and recieve outputs.
type CircuitRuntime interface {
	// Init provides the circuit runtime with the circuit's metadata.
	Init(ctx context.Context, md circuits.Metadata, nid sessions.NodeID) (err error)

	// Eval runs the circuit evaluation, given the circuit.
	Eval(ctx context.Context, c circuits.Circuit) (err error)

	// IncomingOperand provides the circuit runtime with an incoming operand.
	IncomingOperand(circuits.Operand) error

	// GetOperand returns the operand with the given label, if it exists.
	GetOperand(context.Context, circuits.OperandLabel) (*circuits.Operand, bool)

	// GetFutureOperand returns the future operand with the given label, if it exists.
	GetFutureOperand(context.Context, circuits.OperandLabel) (*circuits.FutureOperand, bool)
}

// InputProvider is a type for providing input to a circuit.
// It is provided by the user, and is called by the framework upon circuit execution.
// The framework expects the participant's inputs to be provided through the channel, with their full operand label set.
// If the Input.OperandValue field is a plaintext value, the framework takes care of the encryption.
//
// The following types of OperandValue are supported:
// - *rlwe.Ciphertext: an already-encrypted input
// - *rlwe.Plaintext: a Lattigo plaintext input, which will be encrypted by the framework
// - []uint64: a Go plaintext input, which will be encoded and encrypted by the framework
type InputProvider func(context.Context, sessions.Session, circuits.Descriptor) (chan circuits.Input, error)

// NoInput is an input provider that returns nil for all inputs.
var NoInput InputProvider = func(context.Context, sessions.Session, circuits.Descriptor) (chan circuits.Input, error) {
	return nil, fmt.Errorf("node has no input")
}

// OutputReceiver is a type for receiving outputs from a circuit.
type OutputReceiver chan<- circuits.Output

// NoOutput is an output receiver that do not send any input
var NoOutput OutputReceiver = make(OutputReceiver)

// ServiceConfig is the configuration of a compute service.
type ServiceConfig struct {
	// CircQueueSize is the size of the circuit execution queue.
	// Passed this size, attempting to queue circuit for execution will block.
	CircQueueSize int
	// MaxCircuitEvaluation is the maximum number of circuits that can be evaluated concurrently.
	MaxCircuitEvaluation int
}

// Coordinator is the interface through which the service receives and publishes
// circuit events. It mirrors protocols.Coordinator for circuit events.
type Coordinator interface {
	// Register subscribes to the circuit events: past holds the events emitted before the
	// registration, live delivers the following ones and is closed when coordination ends.
	Register(ctx context.Context) (past []circuits.Event, live <-chan circuits.Event, err error)
	// Publish appends a circuit event emitted by the evaluator.
	Publish(ctx context.Context, ev circuits.Event) error
}

// ProtocolEngine is the interface of the protocol engine required by the service.
// It is implemented by *protocols.MHEMPC.
type ProtocolEngine interface {
	AwaitCompleted(ctx context.Context, sig protocols.Signature) (protocols.Descriptor, error)
	GetOutput(ctx context.Context, pd protocols.Descriptor) (*protocols.Output, error)
}

// KeyOperationRunner is the interface for requesting the execution of key operations
// (e.g., key switching), as required by the evaluator. It is implemented by
// *protocols.CentralCoordinator.
type KeyOperationRunner interface {
	RunSignature(ctx context.Context, sig protocols.Signature) error
}

// Service represents a compute service instance.
type Service struct {
	config ServiceConfig
	self   sessions.NodeID

	sess         *sessions.Session
	sessProvider sessions.Provider
	engine       ProtocolEngine
	runner       KeyOperationRunner
	transport    Transport
	coord        Coordinator

	pubkeyBackend circuits.PublicKeyProvider

	inputProvider InputProvider
	localOutputs  chan circuits.Output

	outputsMu sync.RWMutex
	outputs   map[circuits.OperandLabel]*circuits.Operand

	queuedCircuits chan circuits.Descriptor

	runningCircuitsMu   sync.RWMutex
	runningCircuitsCond *sync.Cond
	runningCircuits     map[sessions.CircuitID]CircuitRuntime

	completedCircuits chan circuits.Descriptor

	opStoreMu sync.RWMutex
	opStore   map[circuits.OperandLabel]*circuits.Operand

	// circuit library
	library map[circuits.Name]circuits.Circuit
}

const (
	// DefaultCircQueueSize is the default size of the circuit execution queue.
	DefaultCircQueueSize = 512
	// DefaultMaxCircuitEvaluation is the default maximum number of circuits that can be evaluated concurrently.
	DefaultMaxCircuitEvaluation = 10
)

// NewComputeService creates a new compute service instance for the given node and session.
// The engine provides the key-switching protocols' outputs, and the runner (nil for nodes that
// never evaluate circuits) requests their execution.
func NewComputeService(ownID sessions.NodeID, sess *sessions.Session, conf ServiceConfig, engine ProtocolEngine, runner KeyOperationRunner, pkbk circuits.PublicKeyProvider) (s *Service, err error) {
	if sess == nil {
		return nil, fmt.Errorf("session must not be nil")
	}
	if engine == nil {
		return nil, fmt.Errorf("protocol engine must not be nil")
	}

	s = new(Service)

	s.config = conf
	if s.config.CircQueueSize == 0 {
		s.config.CircQueueSize = DefaultCircQueueSize
	}
	if s.config.MaxCircuitEvaluation == 0 {
		s.config.MaxCircuitEvaluation = DefaultMaxCircuitEvaluation
	}

	s.self = ownID
	s.sess = sess
	s.sessProvider = sess
	s.engine = engine
	s.runner = runner

	s.pubkeyBackend = sessions.NewCachedPublicKeyBackend(pkbk)

	s.queuedCircuits = make(chan circuits.Descriptor, s.config.CircQueueSize)

	s.runningCircuits = make(map[sessions.CircuitID]CircuitRuntime)
	s.runningCircuitsCond = sync.NewCond(&s.runningCircuitsMu)

	s.opStore = make(map[circuits.OperandLabel]*circuits.Operand)

	s.localOutputs = make(chan circuits.Output)
	s.outputs = make(map[circuits.OperandLabel]*circuits.Operand)

	return s, nil
}

// RegisterCircuit registers a circuit to the service's library.
// It returns an error if the circuit is already registered.
func (s *Service) RegisterCircuit(name circuits.Name, circ circuits.Circuit) error {
	if s.library == nil {
		s.library = make(map[circuits.Name]circuits.Circuit)
	}
	if _, has := s.library[name]; has {
		return fmt.Errorf("circuit name \"%s\" already registered", name)
	}
	s.library[name] = circ
	return nil
}

// RegisterCircuits registers a set of circuits to the service's library.
// It returns an error if any of the circuits is already registered.
func (s *Service) RegisterCircuits(cs map[circuits.Name]circuits.Circuit) error {
	for cn, c := range cs {
		if err := s.RegisterCircuit(cn, c); err != nil {
			return err
		}
	}
	return nil
}

func recoverPresentState(events []circuits.Event) (completedCirc, failedCirc, runningCirc []circuits.Descriptor, err error) {
	runCircuit := make(map[sessions.CircuitID]circuits.Descriptor)
	for _, ev := range events {
		cid := ev.CircuitID
		switch ev.EventType {
		case circuits.Started:
			runCircuit[cid] = ev.Descriptor
		case circuits.Executing:
			if _, has := runCircuit[cid]; !has {
				return nil, nil, nil, fmt.Errorf("inconsisted state, circuit %s execution event before start", cid)
			}
		case circuits.Completed, circuits.Failed:
			if _, has := runCircuit[cid]; !has {
				return nil, nil, nil, fmt.Errorf("inconsisted state, circuit %s termination event before start", cid)
			}
			delete(runCircuit, cid)
			if ev.EventType == circuits.Completed {
				completedCirc = append(completedCirc, ev.Descriptor)
			} else {
				failedCirc = append(failedCirc, ev.Descriptor)
			}
		}
	}

	for _, rc := range runCircuit {
		runningCirc = append(runningCirc, rc)
	}

	return
}

// init initializes the compute service with the currently completed and running circuits.
// It queues running circuits for execution and completed circuits for output retrieval.
func (s *Service) init(ctx context.Context, past []circuits.Event) error {

	complCd, failCd, runCd, err := recoverPresentState(past)
	if err != nil {
		return err
	}

	// stacks the completed circuit in a queue for processing by Run
	s.completedCircuits = make(chan circuits.Descriptor, len(complCd))
	for _, ccd := range complCd {
		s.completedCircuits <- ccd
	}

	// create and queues the running circuits
	for _, rcd := range runCd {
		if s.isEvaluator(rcd) {
			continue // TODO: recovery of the evaluator's running circuits
		}
		if err := s.createCircuit(ctx, rcd); err != nil {
			return err
		}
		s.queuedCircuits <- rcd
	}

	s.Logf("service initialized circuits with %d completed, %d failed and %d running (present=%d)", len(complCd), len(failCd), len(runCd), len(past))

	return nil
}

// Run runs the compute service. The service evaluates the circuits described in cdescs (evaluator
// role, cdescs may be nil if the node never evaluates circuits) and takes part in the circuits
// announced by the coordinator (participant role).
// In the evaluator role, the method returns when cdescs is closed and all circuits are evaluated.
// In the participant role, it returns when the coordinator closes the event stream and all circuits are done.
func (s *Service) Run(ctx context.Context, ip InputProvider, or OutputReceiver, coord Coordinator, trans Transport, cdescs <-chan circuits.Descriptor) error {

	s.Logf("starting service.Run")

	s.transport = trans
	s.inputProvider = ip
	s.coord = coord

	serviceCtx, cancelRunCtx := context.WithCancel(context.WithValue(sessions.ContextWithNodeID(ctx, s.self), services.CtxKeyName, "compute"))
	defer cancelRunCtx()

	// registers to the coordinator
	past, live, err := coord.Register(serviceCtx)
	if err != nil {
		return fmt.Errorf("error registering to coordinator: %w", err)
	}

	// sends the local outputs to the output receiver if any
	outputsForwarded := make(chan struct{})
	go func() {
		defer close(outputsForwarded)
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

	// processes the circuit execution queue
	evalRoutines, erctx := errgroup.WithContext(serviceCtx)
	for i := 0; i < s.config.MaxCircuitEvaluation; i++ {
		evalRoutines.Go(func() error {
			for cd := range s.queuedCircuits {
				if err := s.runCircuit(erctx, cd); err != nil {
					s.Logf("error during circuit execution %s: %v", cd.CircuitID, err)
					return err
				}
			}
			return nil
		})
	}

	// initializes the service from the current state of the circuits
	if err = s.init(serviceCtx, past); err != nil {
		close(s.queuedCircuits)
		_ = evalRoutines.Wait()
		close(s.localOutputs)
		<-outputsForwarded
		return fmt.Errorf("error while initializing service: %w", err)
	}

	// fetches the output for completed circuits (peer nodes only, init sends completed circuits to this queue)
	go func() {
		for cd := range s.completedCircuits {
			if or == nil {
				continue
			}
			if err := s.fetchCompletedOutputs(serviceCtx, cd); err != nil {
				s.Logf("error while fetching outputs of completed circuit %s: %v", cd.CircuitID, err)
			}
		}
	}()
	close(s.completedCircuits)

	// processes the live circuit events
	eventsDone := make(chan struct{})
	go func() {
		defer close(eventsDone)
		for ev := range live {
			if err := s.handleCircuitEvent(serviceCtx, ev); err != nil {
				s.Logf("error while processing event %s: %v", ev, err)
			}
		}
		s.Logf("coordinator closed the circuit event stream")
	}()

	if cdescs != nil {
		// evaluator role: circuits to evaluate come from cdescs
		for cd := range cdescs {
			if err := s.EvalCircuit(serviceCtx, cd); err != nil {
				s.Logf("cannot evaluate circuit %s: %v", cd.CircuitID, err)
			}
		}
		s.Logf("circuit descriptor channel closed")
	} else {
		// participant role: circuits come from the coordinator
		<-eventsDone
	}
	close(s.queuedCircuits)

	err = evalRoutines.Wait()
	s.Logf("all circuits done")

	close(s.localOutputs)
	<-outputsForwarded

	s.Logf("service.Run returns")
	return err
}

// handleCircuitEvent processes a circuit event from the coordinator.
func (s *Service) handleCircuitEvent(ctx context.Context, ev circuits.Event) error {
	cd := ev.Descriptor
	if s.isEvaluator(cd) {
		return nil // own events
	}
	switch ev.EventType {
	case circuits.Started:
		s.runningCircuitsMu.RLock()
		_, running := s.runningCircuits[cd.CircuitID]
		s.runningCircuitsMu.RUnlock()
		if running {
			return nil
		}
		if err := s.createCircuit(ctx, cd); err != nil {
			return err
		}
		s.queuedCircuits <- cd
	case circuits.Completed, circuits.Failed:
		s.runningCircuitsMu.Lock()
		delete(s.runningCircuits, cd.CircuitID)
		s.runningCircuitsMu.Unlock()
	}
	return nil
}

// fetchCompletedOutputs retrieves this node's outputs for an already completed circuit.
func (s *Service) fetchCompletedOutputs(ctx context.Context, cd circuits.Descriptor) error {
	c, has := s.library[cd.Name]
	if !has {
		return fmt.Errorf("no registered circuit for name \"%s\"", cd.Name)
	}

	cinf, err := circuits.Parse(c, cd, s.sess)
	if err != nil {
		return err
	}

	for opl := range cinf.OutputsFor[s.self] {
		ct, err := s.transport.GetCiphertext(ctx, sessions.CiphertextID(opl))
		if err != nil {
			return err
		}
		s.localOutputs <- circuits.Output{CircuitID: cd.CircuitID, Operand: circuits.Operand{OperandLabel: opl, Ciphertext: &ct.Ciphertext}}
	}
	return nil
}

type CircuitNotRunningError struct { // TODO: use more generally
	CircuitID sessions.CircuitID
}

func (e CircuitNotRunningError) Error() string {
	return fmt.Sprintf("circuit %s is not running", e.CircuitID)
}

// validateCircuitDescriptor checks that a circuit descriptor is valid and can be executed by
// the service.
func (s *Service) validateCircuitDescriptor(cd circuits.Descriptor) error {
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

func (s *Service) createCircuit(ctx context.Context, cd circuits.Descriptor) (err error) {
	var cr CircuitRuntime

	if err := s.validateCircuitDescriptor(cd); err != nil {
		return fmt.Errorf("invalid circuit descriptor: %w", err)
	}

	if s.isEvaluator(cd) {
		if s.runner == nil {
			return fmt.Errorf("node has no key operation runner and cannot evaluate circuits")
		}
		cr = &evaluatorRuntime{
			ctx:         ctx,
			cd:          cd,
			sess:        s.sess,
			pkProvider:  s.pubkeyBackend,
			engine:      s.engine,
			runner:      s.runner,
			fheProvider: s,
			opProvider:  s,
		}
	} else {
		cr = &participantRuntime{
			ctx:           ctx,
			cd:            cd,
			sess:          s.sess,
			inputProvider: s.inputProvider,
			or:            s.localOutputs,
			trans:         s.transport,
			engine:        s.engine,
			fheProvider:   s,
		}
	}
	s.runningCircuitsMu.Lock()
	_, has := s.runningCircuits[cd.CircuitID]
	if has {
		s.runningCircuitsMu.Unlock()
		return fmt.Errorf("circuit with id %s is already runnning", cd.CircuitID)
	}
	s.runningCircuits[cd.CircuitID] = cr
	s.runningCircuitsCond.Broadcast()
	s.runningCircuitsMu.Unlock()

	s.Logf("created circuit %s", cd.CircuitID)
	return
}

// awaitCircuit returns the runtime of circuit cid, waiting for its creation if necessary.
func (s *Service) awaitCircuit(ctx context.Context, cid sessions.CircuitID) (CircuitRuntime, error) {
	s.runningCircuitsMu.Lock()
	defer s.runningCircuitsMu.Unlock()
	stop := context.AfterFunc(ctx, func() {
		s.runningCircuitsMu.Lock()
		s.runningCircuitsCond.Broadcast()
		s.runningCircuitsMu.Unlock()
	})
	defer stop()
	for {
		if c, has := s.runningCircuits[cid]; has {
			return c, nil
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("circuit %s not running: %w", cid, ctx.Err())
		}
		s.runningCircuitsCond.Wait()
	}
}

func (s *Service) runCircuit(ctx context.Context, cd circuits.Descriptor) (err error) {

	s.Logf("start running circuit %s", cd.CircuitID)

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

	cinf, err := circuits.Parse(c, cd, s.sess)
	if err != nil {
		return err
	}

	err = cinst.Init(ctx, *cinf, s.self)
	if err != nil {
		return fmt.Errorf("error at circuit initialization: %w", err)
	}

	if s.isEvaluator(cd) {
		err = s.runCircuitAsEvaluator(ctx, c, cinst, *cinf)
	} else {
		err = s.runCircuitAsParticipant(ctx, c, cinst, *cinf)
	}

	return err
}

func (s *Service) runCircuitAsEvaluator(ctx context.Context, c circuits.Circuit, ev CircuitRuntime, md circuits.Metadata) (err error) {
	cd := md.Descriptor
	s.Logf("started circuit %s as evaluator", cd.CircuitID)

	if err := s.coord.Publish(ctx, circuits.Event{EventType: circuits.Started, Descriptor: cd}); err != nil {
		return fmt.Errorf("cannot publish circuit start: %w", err)
	}

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
		s.localOutputs <- circuits.Output{CircuitID: cd.CircuitID, Operand: *fop}
	}

	if err := s.coord.Publish(ctx, circuits.Event{EventType: circuits.Completed, Descriptor: cd}); err != nil {
		return fmt.Errorf("cannot publish circuit completion: %w", err)
	}

	s.runningCircuitsMu.Lock()
	delete(s.runningCircuits, cd.CircuitID)
	nRunning := len(s.runningCircuits)
	s.runningCircuitsMu.Unlock()

	s.Logf("completed circuit %s as evaluator, %d running", cd.CircuitID, nRunning)

	return nil
}

func (s *Service) runCircuitAsParticipant(ctx context.Context, c circuits.Circuit, part CircuitRuntime, md circuits.Metadata) error {

	s.Logf("started circuit %s as participant, has input: %v, has output: %v", md.Descriptor.CircuitID, s.isInputProvider(md), s.isOutputReceiver(md))

	err := part.Eval(ctx, c)
	if err != nil {
		return err
	}

	s.Logf("completed circuit %s as participant", md.Descriptor.CircuitID)

	return nil
}

// EvalCircuit queues the circuit described by cd for evaluation by this node.
func (s *Service) EvalCircuit(ctx context.Context, cd circuits.Descriptor) error {
	if !s.isEvaluator(cd) {
		return fmt.Errorf("node %s is not the evaluator of circuit %s", s.self, cd.CircuitID)
	}
	err := s.createCircuit(ctx, cd)
	if err != nil {
		return err
	}
	s.queuedCircuits <- cd
	return nil
}

// Transport interface

// GetCiphertext retreives a ciphertext from the corresponding circuit runtime.
// The runtime is identified by the circuit ID part of the ciphertext ids.
func (s *Service) GetCiphertext(ctx context.Context, ctID sessions.CiphertextID) (*sessions.Ciphertext, error) {

	_, exists := s.sessProvider.GetSessionFromContext(ctx)
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

	cid := sessions.CircuitID(ctURL.CircuitID())
	if len(cid) == 0 {
		return nil, fmt.Errorf("ciphertext label does not include a circuit ID")
	}

	var ct *sessions.Ciphertext
	var op *circuits.Operand
	var isOutput, isInCircuit bool
	s.outputsMu.RLock()
	op, isOutput = s.outputs[circuits.OperandLabel(ctID)]
	s.outputsMu.RUnlock()
	if !isOutput {
		s.runningCircuitsMu.RLock()
		evalCtx, envExists := s.runningCircuits[cid]
		s.runningCircuitsMu.RUnlock()
		if !envExists {
			return nil, fmt.Errorf("%s is not an output and circuit %s is not running", ctID, ctURL.CircuitID())
		}
		op, isInCircuit = evalCtx.GetOperand(ctx, circuits.OperandLabel(ctURL.String()))
	}

	if !isOutput && !isInCircuit {
		return nil, fmt.Errorf("ciphertext with id %s not found for circuit %s", ctID, ctURL.CircuitID())
	}

	ct = &sessions.Ciphertext{Ciphertext: *op.Ciphertext}
	return ct, nil
}

// PutCiphertext provides the ciphertext to the corresponding circuit runtime.
// The runtime is identified by the circuit ID part of the ciphertext ids.
func (s *Service) PutCiphertext(ctx context.Context, ct sessions.Ciphertext) error {

	_, exists := s.sessProvider.GetSessionFromContext(ctx)
	if !exists {
		sessid, _ := sessions.IDFromContext(ctx)
		return fmt.Errorf("invalid session id \"%s\"", sessid)
	}

	ctURL, err := ParseURL(string(ct.ID))
	if err != nil {
		return fmt.Errorf("invalid ciphertext id \"%s\": %w", ct.ID, err)
	}

	cid := sessions.CircuitID(ctURL.CircuitID())

	if len(cid) == 0 {
		return fmt.Errorf("ciphertext label does not include a circuit ID")
	}

	s.runningCircuitsMu.RLock()
	c, envExists := s.runningCircuits[cid]
	s.runningCircuitsMu.RUnlock()
	if !envExists {
		return fmt.Errorf("for unknown circuit %s", cid)
	}

	op := circuits.Operand{OperandLabel: circuits.OperandLabel(ct.ID), Ciphertext: &ct.Ciphertext}
	err = c.IncomingOperand(op)
	if err != nil {
		return err
	}

	s.Logf("recieved ciphertext for operand %s", op.OperandLabel)

	return nil
}

// GetKeySwitchInput returns the input of a key-switching protocol from the corresponding circuit runtime.
// The input ciphertext is identified by the "op" protocol argument, and the runtime by the circuit ID
// part of the operand label. The method waits for the circuit to be created if necessary.
// It is meant to be used as the protocols.KeySwitchInputProvider of the node's engine.
func (s *Service) GetKeySwitchInput(ctx context.Context, pd protocols.Descriptor) (*protocols.KeySwitchInput, error) {

	opl, has := pd.Signature.Args["op"]
	if !has {
		return nil, fmt.Errorf("invalid protocol descriptor: no operand specified")
	}

	c, err := s.awaitCircuit(ctx, circuits.OperandLabel(opl).CircuitID())
	if err != nil {
		return nil, err
	}

	op, has := c.GetOperand(ctx, circuits.OperandLabel(opl))
	if !has {
		return nil, fmt.Errorf("invalid protocol descriptor: operand label %s not in circuit", opl)
	}

	ksin := &protocols.KeySwitchInput{InpuCt: op.Ciphertext}
	switch pd.Signature.Type {
	case protocols.DEC:
		ksin.OutputKey = rlwe.NewSecretKey(s.sess.Params) // TODO put in session
	case protocols.CKS, protocols.PCKS:
		return nil, fmt.Errorf("key switch protocol not supported yet") // TODO
	default:
		return nil, fmt.Errorf("invalid protocol type: %s", pd.Signature.Type)
	}
	return ksin, nil
}

// FHEProvider interface

// GetParameters returns the parameters of the context's session.
func (s *Service) GetParameters(ctx context.Context) (sessions.FHEParameters, error) {
	if sess, has := s.sessProvider.GetSessionFromContext(ctx); has {
		return sess.Params, nil
	}
	return nil, fmt.Errorf("no session found for context")
}

// GetEncoder returns a new encoder from the context's session.
func (s *Service) GetEncoder(ctx context.Context) (enc Encoder, err error) {

	sess, has := s.sessProvider.GetSessionFromContext(ctx)
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

	sess, has := s.sessProvider.GetSessionFromContext(ctx)
	if !has {
		return nil, fmt.Errorf("no session found for this context")
	}

	cpk, err := s.pubkeyBackend.GetCollectivePublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot retrieve the collective public key : %w", err)
	}

	return rlwe.NewEncryptor(sess.Params, cpk), nil
}

// GetDecryptor returns a new decryptor from the context's session.
// The decryptor is inialized with a secret key of 0.
func (s *Service) GetDecryptor(ctx context.Context) (*rlwe.Decryptor, error) {
	sess, has := s.sessProvider.GetSessionFromContext(ctx)
	if !has {
		return nil, fmt.Errorf("no session found for this context")
	}

	return rlwe.NewDecryptor(sess.Params, rlwe.NewSecretKey(sess.Params)), nil // decryptor under sk=0 (sk is determined at output)

}

func (s *Service) PutOperand(opl circuits.OperandLabel, op *circuits.Operand) error {
	s.opStoreMu.Lock()
	s.opStore[opl] = op
	s.opStoreMu.Unlock()
	return nil
}

func (s *Service) GetOperand(opl circuits.OperandLabel) (*circuits.Operand, bool) {
	s.opStoreMu.RLock()
	op, has := s.opStore[opl]
	s.opStoreMu.RUnlock()
	return op, has
}

func (s *Service) isInputProvider(md circuits.Metadata) bool {
	return len(md.InputsFor[s.self]) > 0
}

func (s *Service) isOutputReceiver(md circuits.Metadata) bool {
	return len(md.OutputsFor[s.self]) > 0
}

func (s *Service) isEvaluator(cd circuits.Descriptor) bool {
	return cd.Evaluator == s.self
}

func (s *Service) Logf(msg string, v ...any) {
	log.Printf("%s | [compute] %s\n", s.self, fmt.Sprintf(msg, v...))
}
