package circuits

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"sync"

	"github.com/ChristianMct/helium/sessions"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
)

const defaultMaxEvaluation = 8 // max number of concurrent circuit evaluations

// ErrCircuitNotRunning is returned when an input refers to a circuit that is not
// currently running at this node.
var ErrCircuitNotRunning = errors.New("circuit is not running")

// Config is the configuration of a compute Engine.
type Config struct {
	// MaxEvaluation is the maximum number of circuits evaluated concurrently by this node.
	MaxEvaluation int
}

// OperandTransport is the transport interface required by the Engine. Operands are routed
// by the transport from the circuit descriptor (inputs go to the evaluator) or from
// the operand id (an operand is queried from its owner). Incoming operands are
// delivered to the engine by calling its HandleOperand method.
type OperandTransport interface {
	// PutOperand sends an input operand of circuit cd to its evaluator.
	PutOperand(ctx context.Context, cd Descriptor, op Operand) error
	// GetOperand queries an operand from its owner.
	GetOperand(ctx context.Context, id OperandID) (*Operand, error)
}

// InputProvider is the user-provided function called by the engine to obtain the node's
// inputs to a circuit. It is called once per circuit evaluation with the ids of the operands
// the node must provide, and returns a channel delivering them. The channel must be closed
// once all inputs are sent.
type InputProvider func(ctx context.Context, cd Descriptor, ids []OperandID) (<-chan Input, error)

// Input is a node's input to a circuit. The following value types are supported:
//   - *rlwe.Ciphertext: an already-encrypted input (not supported for summed inputs),
//   - *rlwe.Plaintext: a Lattigo plaintext, encrypted by the engine,
//   - a Go slice supported by the session's scheme encoder (e.g., []uint64 for BGV,
//     []float64 for CKKS), encoded and encrypted by the engine.
type Input struct {
	ID    OperandID
	Value any
}

// NoInput is an InputProvider for nodes that never provide inputs.
var NoInput InputProvider = func(context.Context, Descriptor, []OperandID) (<-chan Input, error) {
	return nil, fmt.Errorf("node has no input")
}

// Engine is the state of a node in the circuit evaluations of a session.
//
// The type is a state machine driven by the coordination events of a Coordinator
// (HandleEvent) and by incoming operands (HandleOperand). It executes the circuits
// described by the events, in the roles the descriptors assign to the node, and
// publishes its progress back to the coordinator:
//   - Started: the circuit is registered; as evaluator, the evaluation is started
//     and an Executing event is published,
//   - Executing: as input provider, the node's inputs are encrypted and sent,
//   - Completed: the outputs are available (published by the evaluator),
//   - Failed: the circuit is dropped (published by the evaluator on evaluation error).
//
// All inputs are processed synchronously under a single lock; the asynchronous work
// (circuit evaluation, input provision) runs in goroutines started by the state machine.
// The outputs of completed circuits are held in an operand store and fetched lazily
// from their owner when not available locally (see GetOperand).
type Engine struct {
	self    sessions.NodeID
	sess    *sessions.Session
	conf    Config
	trans   OperandTransport
	keys    sessions.PublicKeyProvider
	inputs  InputProvider
	library map[Name]Circuit

	mu          sync.Mutex
	running     map[sessions.CircuitID]*runningCircuit
	completed   map[sessions.CircuitID]Descriptor
	failed      map[sessions.CircuitID]Descriptor
	waiters     map[sessions.CircuitID][]chan completion
	idleWaiters []chan struct{}
	operands    map[OperandID]*Operand
	outbox      []Event
	publishing  bool // whether events are being published (outside of the lock)
	notify      chan struct{}

	evalSem chan struct{}
	wg      sync.WaitGroup
}

// runningCircuit is the engine state for a running circuit.
type runningCircuit struct {
	cd      Descriptor
	md      *Metadata
	circuit Circuit
	ctx     context.Context

	executing       bool // whether the evaluator is ready to receive inputs
	evalStarted     bool // evaluator: whether the evaluation has been started
	inputsScheduled bool // participant: whether the input provision has been scheduled

	// evaluator only
	inputs  map[OperandID]*FutureOperand
	outputs map[string]*OutputOperand
	sumsMu  sync.Mutex
	sums    map[string]*FutureOperand

	done chan struct{} // closed when the circuit leaves the running state
}

// NewEngine creates a new engine for the given node and session. The key provider
// provides the collective public key (to encrypt inputs) and the evaluation keys
// (to evaluate circuits). Circuits are registered with RegisterCircuit and the
// node's inputs are provided by the InputProvider set with SetInputProvider.
func NewEngine(self sessions.NodeID, sess *sessions.Session, conf Config, trans OperandTransport, keys sessions.PublicKeyProvider) (*Engine, error) {
	if sess == nil {
		return nil, fmt.Errorf("session must not be nil")
	}
	if trans == nil {
		return nil, fmt.Errorf("transport must not be nil")
	}
	if keys == nil {
		return nil, fmt.Errorf("key provider must not be nil")
	}
	if conf.MaxEvaluation <= 0 {
		conf.MaxEvaluation = defaultMaxEvaluation
	}
	return &Engine{
		self:      self,
		sess:      sess,
		conf:      conf,
		trans:     trans,
		keys:      keys,
		inputs:    NoInput,
		library:   make(map[Name]Circuit),
		running:   make(map[sessions.CircuitID]*runningCircuit),
		completed: make(map[sessions.CircuitID]Descriptor),
		failed:    make(map[sessions.CircuitID]Descriptor),
		waiters:   make(map[sessions.CircuitID][]chan completion),
		operands:  make(map[OperandID]*Operand),
		notify:    make(chan struct{}, 1),
		evalSem:   make(chan struct{}, conf.MaxEvaluation),
	}, nil
}

// NodeID returns the id of the node running this engine.
func (e *Engine) NodeID() sessions.NodeID {
	return e.self
}

// Session returns the session of this engine.
func (e *Engine) Session() *sessions.Session {
	return e.sess
}

// RegisterCircuit registers a circuit to the engine's library.
// It returns an error if the circuit is already registered.
func (e *Engine) RegisterCircuit(name Name, c Circuit) error {
	if c.Eval == nil {
		return fmt.Errorf("circuit %s has no evaluation function", name)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, has := e.library[name]; has {
		return fmt.Errorf("circuit name \"%s\" already registered", name)
	}
	e.library[name] = c
	return nil
}

// RegisterCircuits registers a set of circuits to the engine's library.
// It returns an error if any of the circuits is already registered.
func (e *Engine) RegisterCircuits(cs map[Name]Circuit) error {
	for name, c := range cs {
		if err := e.RegisterCircuit(name, c); err != nil {
			return err
		}
	}
	return nil
}

// SetInputProvider sets the function providing the node's inputs to
func (e *Engine) SetInputProvider(ip InputProvider) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if ip == nil {
		ip = NoInput
	}
	e.inputs = ip
}

// ---- roles

func (e *Engine) isEvaluator(md *Metadata) bool {
	return md.IsEvaluator(e.self)
}

func (e *Engine) isParticipant(md *Metadata) bool {
	return md.IsParticipant(e.self)
}

// resolve resolves the descriptor against the library and the session.
func (e *Engine) resolve(cd Descriptor) (*Metadata, Circuit, error) {
	c, has := e.library[cd.Name]
	if !has {
		return nil, Circuit{}, fmt.Errorf("no registered circuit for name \"%s\"", cd.Name)
	}
	itf, err := c.Describe(cd.Signature, e.sess.Params)
	if err != nil {
		return nil, Circuit{}, fmt.Errorf("cannot describe circuit %s: %w", cd.Signature, err)
	}
	md, err := Resolve(cd, itf, e.sess.Nodes)
	if err != nil {
		return nil, Circuit{}, fmt.Errorf("cannot resolve circuit %s: %w", cd.HID(), err)
	}
	return md, c, nil
}

// Validate returns an error if the circuit described by cd cannot be evaluated
// with the engine's library and session.
func (e *Engine) Validate(cd Descriptor) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, _, err := e.resolve(cd)
	return err
}

// Metadata returns the resolved metadata of the circuit described by cd.
func (e *Engine) Metadata(cd Descriptor) (*Metadata, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	md, _, err := e.resolve(cd)
	return md, err
}

// ---- state machine inputs

// Init initializes the engine state from a log of past coordination events
// (catch-up). The events are applied without side effects; the actions required
// by the resulting state are then taken at once.
func (e *Engine) Init(ctx context.Context, events []Event) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, ev := range events {
		if err := e.apply(ctx, ev); err != nil {
			return fmt.Errorf("error applying event %s: %w", ev, err)
		}
	}
	e.reconcile()
	return nil
}

// HandleEvent processes a coordination event. It is idempotent with respect to
// duplicated events, and tolerates receiving events about circuits in which
// the node has no role.
func (e *Engine) HandleEvent(ctx context.Context, ev Event) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.apply(ctx, ev); err != nil {
		return err
	}
	e.reconcile()
	return nil
}

// HandleOperand processes an input operand sent by a participant in a circuit for
// which this node is the evaluator. It returns ErrCircuitNotRunning if the circuit
// is not running at this node.
func (e *Engine) HandleOperand(_ context.Context, op Operand) error {
	if err := op.ID.Validate(); err != nil {
		return err
	}
	if op.Ciphertext == nil {
		return fmt.Errorf("operand %s has no ciphertext", op.ID)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	rc, has := e.running[op.ID.CircuitID()]
	if !has {
		return fmt.Errorf("%w: %s", ErrCircuitNotRunning, op.ID.CircuitID())
	}
	if !e.isEvaluator(rc.md) {
		return fmt.Errorf("node %s is not the evaluator of circuit %s", e.self, rc.cd.HID())
	}
	fop, expected := rc.inputs[op.ID]
	if !expected {
		return fmt.Errorf("unexpected operand %s for circuit %s", op.ID, rc.cd.HID())
	}
	fop.Set(op.Ciphertext)
	return nil
}

// ---- state transitions (caller holds e.mu)

// apply applies a coordination event to the state, without side effects.
func (e *Engine) apply(ctx context.Context, ev Event) error {
	cd := ev.Descriptor
	cid := cd.CircuitID
	switch ev.EventType {
	case Started:
		if _, has := e.completed[cid]; has {
			return nil
		}
		if _, has := e.running[cid]; has {
			return nil
		}
		md, c, err := e.resolve(cd)
		if err != nil {
			return err
		}
		rc := &runningCircuit{cd: cd, md: md, circuit: c, ctx: ctx, done: make(chan struct{})}
		if e.isEvaluator(md) {
			rc.inputs = make(map[OperandID]*FutureOperand)
			for _, id := range md.ExpectedInputs() {
				rc.inputs[id] = NewFutureOperand(id)
			}
			rc.outputs = make(map[string]*OutputOperand, len(md.Outputs))
			for name, id := range md.Outputs {
				rc.outputs[name] = NewOutputOperand(id)
			}
			rc.sums = make(map[string]*FutureOperand)
		}
		delete(e.failed, cid)
		e.running[cid] = rc
	case Executing:
		if rc, has := e.running[cid]; has {
			rc.executing = true
		}
	case Completed:
		e.markCompleted(cd)
	case Failed:
		if rc, has := e.running[cid]; has {
			e.dropRunning(rc)
		}
		e.markFailed(cd)
	default:
		return fmt.Errorf("unknown event type: %d", ev.EventType)
	}
	return nil
}

// dropRunning removes rc from the running
func (e *Engine) dropRunning(rc *runningCircuit) {
	delete(e.running, rc.cd.CircuitID)
	close(rc.done)
	e.wakeIdle()
}

// idle returns whether the engine has no running circuit and no event left to publish.
func (e *Engine) idle() bool {
	return len(e.running) == 0 && len(e.outbox) == 0 && !e.publishing
}

// wakeIdle releases the AwaitIdle callers if the engine is idle.
func (e *Engine) wakeIdle() {
	if !e.idle() {
		return
	}
	for _, w := range e.idleWaiters {
		close(w)
	}
	e.idleWaiters = nil
}

// markCompleted records cd as completed and wakes up the waiters.
func (e *Engine) markCompleted(cd Descriptor) {
	cid := cd.CircuitID
	if rc, has := e.running[cid]; has {
		e.dropRunning(rc)
	}
	delete(e.failed, cid)
	e.completed[cid] = cd
	for _, w := range e.waiters[cid] {
		w <- completion{cd: cd}
	}
	delete(e.waiters, cid)
}

// markFailed records cd as failed and wakes up the waiters with an error.
func (e *Engine) markFailed(cd Descriptor) {
	cid := cd.CircuitID
	e.failed[cid] = cd
	for _, w := range e.waiters[cid] {
		w <- completion{cd: cd, err: fmt.Errorf("circuit %s failed", cd.HID())}
	}
	delete(e.waiters, cid)
}

// completion is the result of waiting for a circuit's termination.
type completion struct {
	cd  Descriptor
	err error
}

// reconcile derives the actions required by the current state:
//   - as evaluator, publishes Executing and starts the evaluation of newly registered circuits,
//   - as input provider, starts the provision of the node's inputs to executing
//
// It is the only place where side effects are decided.
func (e *Engine) reconcile() {
	for _, rc := range e.running {
		if e.isEvaluator(rc.md) && !rc.evalStarted {
			rc.evalStarted = true
			rc.executing = true
			e.emit(Event{EventType: Executing, Descriptor: rc.cd})
			e.wg.Add(1)
			go e.evaluate(rc)
		}
		if rc.executing && !rc.inputsScheduled && e.isParticipant(rc.md) {
			rc.inputsScheduled = true
			e.wg.Add(1)
			go e.provideInputs(rc)
		}
	}
	e.changed()
}

// evaluate evaluates the circuit rc as evaluator. It runs outside of the lock.
func (e *Engine) evaluate(rc *runningCircuit) {
	defer e.wg.Done()
	ctx := rc.ctx

	select {
	case e.evalSem <- struct{}{}:
		defer func() { <-e.evalSem }()
	case <-rc.done:
		return
	case <-ctx.Done():
		return
	}
	select {
	case <-rc.done:
		return
	default:
	}

	e.Logf("evaluating circuit %s", rc.cd.HID())

	eval, err := e.evaluatorFor(ctx, rc.md.Keys)
	if err != nil {
		e.failLocal(rc, fmt.Errorf("cannot get evaluator: %w", err))
		return
	}

	rt := &engineRuntime{e: e, rc: rc, eval: eval}
	if err := runCircuit(rc.circuit, rt); err != nil {
		e.failLocal(rc, err)
		return
	}

	outs := make([]Operand, 0, len(rc.outputs))
	for name, oo := range rc.outputs {
		op, set := oo.Get()
		if !set {
			e.failLocal(rc, fmt.Errorf("output %s was not set by the circuit", name))
			return
		}
		outs = append(outs, op)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	for i := range outs {
		op := outs[i]
		e.operands[op.ID] = &op
	}
	if _, running := e.running[rc.cd.CircuitID]; !running {
		e.Logf("circuit %s terminated before its evaluation completed", rc.cd.HID())
		return
	}
	e.markCompleted(rc.cd)
	e.emit(Event{EventType: Completed, Descriptor: rc.cd})
	e.Logf("completed circuit %s", rc.cd.HID())
	e.changed()
}

// runCircuit runs the circuit's evaluation function, turning panics into errors.
func runCircuit(c Circuit, rt Runtime) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic during circuit evaluation: %v", r)
		}
	}()
	return c.Eval(rt)
}

// failLocal terminates a circuit evaluated by this node with a failure.
func (e *Engine) failLocal(rc *runningCircuit, cause error) {
	e.Logf("circuit %s failed: %s", rc.cd.HID(), cause)
	e.mu.Lock()
	defer e.mu.Unlock()
	if cur, running := e.running[rc.cd.CircuitID]; !running || cur != rc {
		return // already terminated by an event
	}
	e.dropRunning(rc)
	e.markFailed(rc.cd)
	e.emit(Event{EventType: Failed, Descriptor: rc.cd})
	e.changed()
}

// evaluatorFor returns an evaluator initialized with the given keys.
func (e *Engine) evaluatorFor(ctx context.Context, keys Keys) (Evaluator, error) {
	var rlk *rlwe.RelinearizationKey
	if keys.Rlk {
		var err error
		if rlk, err = e.keys.GetRelinearizationKey(ctx); err != nil {
			return nil, err
		}
	}
	gks := make([]*rlwe.GaloisKey, 0, len(keys.GaloisEls))
	for _, galEl := range keys.GaloisEls {
		gk, err := e.keys.GetGaloisKey(ctx, galEl)
		if err != nil {
			return nil, err
		}
		gks = append(gks, gk)
	}
	return NewEvaluator(e.sess.Params, rlwe.NewMemEvaluationKeySet(rlk, gks...)), nil
}

// provideInputs provides the node's inputs to circuit rc. It runs outside of the lock.
func (e *Engine) provideInputs(rc *runningCircuit) {
	defer e.wg.Done()
	ctx := rc.ctx
	select {
	case <-rc.done:
		return
	default:
	}
	ids := rc.md.InputsOf[e.self]
	if err := e.sendInputs(ctx, rc.md, ids); err != nil {
		e.Logf("error while providing inputs to %s: %s", rc.cd.HID(), err)
		return
	}
	e.Logf("provided %d input(s) to %s", len(ids), rc.cd.HID())
}

// ---- outputs

func (e *Engine) emit(ev Event) {
	e.outbox = append(e.outbox, ev)
	e.changed()
}

// changed signals the Run loop that the state has changed (non-blocking).
func (e *Engine) changed() {
	select {
	case e.notify <- struct{}{}:
	default:
	}
}

// publish sends the emitted events to the coordinator, outside of the lock.
func (e *Engine) publish(ctx context.Context, coord Coordinator) (err error) {
	e.mu.Lock()
	evs := e.outbox
	e.outbox = nil
	e.publishing = true
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		e.publishing = false
		e.wakeIdle()
		e.mu.Unlock()
	}()
	for _, ev := range evs {
		if err := coord.Publish(ctx, ev); err != nil {
			return fmt.Errorf("cannot publish %s: %w", ev, err)
		}
	}
	return nil
}

// Run connects the engine to a coordinator: the engine catches up with the past
// events, processes the live ones with HandleEvent and publishes its own events.
// The method returns when the coordinator closes the live channel, when publishing
// fails, or when the context is cancelled.
func (e *Engine) Run(ctx context.Context, coord Coordinator) (err error) {
	past, live, err := coord.Register(ctx)
	if err != nil {
		return fmt.Errorf("cannot register to coordinator: %w", err)
	}
	if err = e.Init(ctx, past); err != nil {
		return err
	}

	for done := false; !done; {
		select {
		case ev, more := <-live:
			if !more {
				done = true
				continue
			}
			if err = e.HandleEvent(ctx, ev); err != nil {
				done = true
			}
		case <-e.notify:
			if err = e.publish(ctx, coord); err != nil {
				done = true
			}
		case <-ctx.Done():
			err = ctx.Err()
			done = true
		}
	}
	e.wg.Wait()
	if perr := e.publish(ctx, coord); err == nil {
		err = perr
	}
	return err
}

// Logf logs a message with the engine's prefix.
func (e *Engine) Logf(msg string, v ...any) {
	log.Printf("%s | [compute] %s\n", e.self, fmt.Sprintf(msg, v...))
}

// sortedIDs returns a sorted copy of the ids.
func sortedIDs(ids []OperandID) []OperandID {
	s := slices.Clone(ids)
	slices.Sort(s)
	return s
}
