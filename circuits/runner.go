package circuits

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"sync"

	"github.com/ChristianMct/helium"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

const defaultMaxEvaluation = 8 // max number of concurrent circuit evaluations

// ErrCircuitNotRunning is returned when an input refers to a circuit that is not
// currently running at this node.
var ErrCircuitNotRunning = errors.New("circuit is not running")

// Config is the configuration of a Runner.
type Config struct {
	// MaxEvaluation is the maximum number of circuits evaluated concurrently by this node.
	MaxEvaluation int
}

// OperandTransport is the transport interface required by a Runner. Operands are routed
// by the transport from the circuit descriptor (inputs go to the evaluator) or from
// the operand id (an operand is queried from its owner). Incoming operands are
// delivered to the runner by calling its HandleOperand method.
type OperandTransport interface {
	// PutOperand sends an input operand of circuit cd to its evaluator.
	PutOperand(ctx context.Context, cd helium.Descriptor, op helium.Operand) error
	// GetOperand queries an operand from its owner.
	GetOperand(ctx context.Context, id helium.OperandID) (*helium.Operand, error)
}

// InputProvider is the user-provided function called by the runner to obtain the node's
// inputs to a circuit. It is called once per circuit evaluation with the ids of the operands
// the node must provide, and returns a channel delivering them. The channel must be closed
// once all inputs are sent.
type InputProvider func(ctx context.Context, cd helium.Descriptor, ids []helium.OperandID) (<-chan Input, error)

// Input is a node's input to a circuit. The following value types are supported:
//   - *rlwe.Ciphertext: an already-encrypted input (not supported for summed inputs),
//   - *rlwe.Plaintext: a Lattigo plaintext, encrypted by the runner,
//   - a Go slice supported by the session's scheme encoder (e.g., []uint64 for BGV,
//     []float64 for CKKS), encoded and encrypted by the runner.
type Input struct {
	ID    helium.OperandID
	Value any
}

// NoInput is an InputProvider for nodes that never provide inputs.
var NoInput InputProvider = func(context.Context, helium.Descriptor, []helium.OperandID) (<-chan Input, error) {
	return nil, fmt.Errorf("node has no input")
}

// Runner is the state of a node in the circuit evaluations of a session. It is the
// sibling of protocols.Runner, which runs the session's MHE protocols.
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
type Runner struct {
	self    helium.NodeID
	sess    *helium.Session
	conf    Config
	trans   OperandTransport
	keys    helium.PublicKeyProvider
	inputs  InputProvider
	library map[helium.Name]helium.Circuit

	mu          sync.Mutex
	running     map[helium.CircuitID]*runningCircuit
	completed   map[helium.CircuitID]helium.Descriptor
	failed      map[helium.CircuitID]helium.Descriptor
	waiters     map[helium.CircuitID][]chan completion
	idleWaiters []chan struct{}
	operands    map[helium.OperandID]*helium.Operand
	outbox      []Event
	publishing  bool // whether events are being published (outside of the lock)
	notify      chan struct{}

	evalSem chan struct{}
	wg      sync.WaitGroup
}

// runningCircuit is the runner state for a running circuit.
type runningCircuit struct {
	cd      helium.Descriptor
	md      *helium.Metadata
	circuit helium.Circuit
	ctx     context.Context

	executing       bool // whether the evaluator is ready to receive inputs
	evalStarted     bool // evaluator: whether the evaluation has been started
	inputsScheduled bool // participant: whether the input provision has been scheduled

	// evaluator only
	inputs  map[helium.OperandID]*helium.FutureOperand
	outputs map[string]*helium.OutputOperand
	sumsMu  sync.Mutex
	sums    map[string]*helium.FutureOperand

	done chan struct{} // closed when the circuit leaves the running state
}

// NewRunner creates a new runner for the given node and session. The key provider
// provides the collective public key (to encrypt inputs) and the evaluation keys
// (to evaluate circuits). Circuits are registered with RegisterCircuit and the
// node's inputs are provided by the InputProvider set with SetInputProvider.
func NewRunner(self helium.NodeID, sess *helium.Session, conf Config, trans OperandTransport, keys helium.PublicKeyProvider) (*Runner, error) {
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
	return &Runner{
		self:      self,
		sess:      sess,
		conf:      conf,
		trans:     trans,
		keys:      keys,
		inputs:    NoInput,
		library:   make(map[helium.Name]helium.Circuit),
		running:   make(map[helium.CircuitID]*runningCircuit),
		completed: make(map[helium.CircuitID]helium.Descriptor),
		failed:    make(map[helium.CircuitID]helium.Descriptor),
		waiters:   make(map[helium.CircuitID][]chan completion),
		operands:  make(map[helium.OperandID]*helium.Operand),
		notify:    make(chan struct{}, 1),
		evalSem:   make(chan struct{}, conf.MaxEvaluation),
	}, nil
}

// NodeID returns the id of the node running this runner.
func (r *Runner) NodeID() helium.NodeID {
	return r.self
}

// Session returns the session of this runner.
func (r *Runner) Session() *helium.Session {
	return r.sess
}

// RegisterCircuit registers a circuit to the runner's library.
// It returns an error if the circuit is already registered.
func (r *Runner) RegisterCircuit(name helium.Name, c helium.Circuit) error {
	if c.Eval == nil {
		return fmt.Errorf("circuit %s has no evaluation function", name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, has := r.library[name]; has {
		return fmt.Errorf("circuit name \"%s\" already registered", name)
	}
	r.library[name] = c
	return nil
}

// RegisterCircuits registers a set of circuits to the runner's library.
// It returns an error if any of the circuits is already registered.
func (r *Runner) RegisterCircuits(cs map[helium.Name]helium.Circuit) error {
	for name, c := range cs {
		if err := r.RegisterCircuit(name, c); err != nil {
			return err
		}
	}
	return nil
}

// SetInputProvider sets the function providing the node's inputs to
func (r *Runner) SetInputProvider(ip InputProvider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ip == nil {
		ip = NoInput
	}
	r.inputs = ip
}

// ---- roles

func (r *Runner) isEvaluator(md *helium.Metadata) bool {
	return md.IsEvaluator(r.self)
}

func (r *Runner) isParticipant(md *helium.Metadata) bool {
	return md.IsParticipant(r.self)
}

// resolve resolves the descriptor against the library and the session.
func (r *Runner) resolve(cd helium.Descriptor) (*helium.Metadata, helium.Circuit, error) {
	c, has := r.library[cd.Name]
	if !has {
		return nil, helium.Circuit{}, fmt.Errorf("no registered circuit for name \"%s\"", cd.Name)
	}
	itf, err := c.Describe(cd.Signature, r.sess.Params)
	if err != nil {
		return nil, helium.Circuit{}, fmt.Errorf("cannot describe circuit %s: %w", cd.Signature, err)
	}
	md, err := helium.Resolve(cd, itf, r.sess.Nodes)
	if err != nil {
		return nil, helium.Circuit{}, fmt.Errorf("cannot resolve circuit %s: %w", cd.HID(), err)
	}
	return md, c, nil
}

// Validate returns an error if the circuit described by cd cannot be evaluated
// with the runner's library and session.
func (r *Runner) Validate(cd helium.Descriptor) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, _, err := r.resolve(cd)
	return err
}

// Metadata returns the resolved metadata of the circuit described by cd.
func (r *Runner) Metadata(cd helium.Descriptor) (*helium.Metadata, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	md, _, err := r.resolve(cd)
	return md, err
}

// ---- state machine inputs

// Init initializes the runner state from a log of past coordination events
// (catch-up). The events are applied without side effects; the actions required
// by the resulting state are then taken at once.
func (r *Runner) Init(ctx context.Context, events []Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ev := range events {
		if err := r.apply(ctx, ev); err != nil {
			return fmt.Errorf("error applying event %s: %w", ev, err)
		}
	}
	r.reconcile()
	return nil
}

// HandleEvent processes a coordination event. It is idempotent with respect to
// duplicated events, and tolerates receiving events about circuits in which
// the node has no role.
func (r *Runner) HandleEvent(ctx context.Context, ev Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.apply(ctx, ev); err != nil {
		return err
	}
	r.reconcile()
	return nil
}

// HandleOperand processes an input operand sent by a participant in a circuit for
// which this node is the evaluator. It returns ErrCircuitNotRunning if the circuit
// is not running at this node.
func (r *Runner) HandleOperand(_ context.Context, op helium.Operand) error {
	if err := op.ID.Validate(); err != nil {
		return err
	}
	if op.Ciphertext == nil {
		return fmt.Errorf("operand %s has no ciphertext", op.ID)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	rc, has := r.running[op.ID.CircuitID()]
	if !has {
		return fmt.Errorf("%w: %s", ErrCircuitNotRunning, op.ID.CircuitID())
	}
	if !r.isEvaluator(rc.md) {
		return fmt.Errorf("node %s is not the evaluator of circuit %s", r.self, rc.cd.HID())
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
func (r *Runner) apply(ctx context.Context, ev Event) error {
	cd := ev.Descriptor
	cid := cd.CircuitID
	switch ev.EventType {
	case Started:
		if _, has := r.completed[cid]; has {
			return nil
		}
		if _, has := r.running[cid]; has {
			return nil
		}
		md, c, err := r.resolve(cd)
		if err != nil {
			return err
		}
		rc := &runningCircuit{cd: cd, md: md, circuit: c, ctx: ctx, done: make(chan struct{})}
		if r.isEvaluator(md) {
			rc.inputs = make(map[helium.OperandID]*helium.FutureOperand)
			for _, id := range md.ExpectedInputs() {
				rc.inputs[id] = helium.NewFutureOperand(id)
			}
			rc.outputs = make(map[string]*helium.OutputOperand, len(md.Outputs))
			for name, id := range md.Outputs {
				rc.outputs[name] = helium.NewOutputOperand(id)
			}
			rc.sums = make(map[string]*helium.FutureOperand)
		}
		delete(r.failed, cid)
		r.running[cid] = rc
	case Executing:
		if rc, has := r.running[cid]; has {
			rc.executing = true
		}
	case Completed:
		r.markCompleted(cd)
	case Failed:
		if rc, has := r.running[cid]; has {
			r.dropRunning(rc)
		}
		r.markFailed(cd)
	default:
		return fmt.Errorf("unknown event type: %d", ev.EventType)
	}
	return nil
}

// dropRunning removes rc from the running
func (r *Runner) dropRunning(rc *runningCircuit) {
	delete(r.running, rc.cd.CircuitID)
	close(rc.done)
	r.wakeIdle()
}

// idle returns whether the runner has no running circuit and no event left to publish.
func (r *Runner) idle() bool {
	return len(r.running) == 0 && len(r.outbox) == 0 && !r.publishing
}

// wakeIdle releases the AwaitIdle callers if the runner is idle.
func (r *Runner) wakeIdle() {
	if !r.idle() {
		return
	}
	for _, w := range r.idleWaiters {
		close(w)
	}
	r.idleWaiters = nil
}

// markCompleted records cd as completed and wakes up the waiters.
func (r *Runner) markCompleted(cd helium.Descriptor) {
	cid := cd.CircuitID
	if rc, has := r.running[cid]; has {
		r.dropRunning(rc)
	}
	delete(r.failed, cid)
	r.completed[cid] = cd
	for _, w := range r.waiters[cid] {
		w <- completion{cd: cd}
	}
	delete(r.waiters, cid)
}

// markFailed records cd as failed and wakes up the waiters with an error.
func (r *Runner) markFailed(cd helium.Descriptor) {
	cid := cd.CircuitID
	r.failed[cid] = cd
	for _, w := range r.waiters[cid] {
		w <- completion{cd: cd, err: fmt.Errorf("circuit %s failed", cd.HID())}
	}
	delete(r.waiters, cid)
}

// completion is the result of waiting for a circuit's termination.
type completion struct {
	cd  helium.Descriptor
	err error
}

// reconcile derives the actions required by the current state:
//   - as evaluator, publishes Executing and starts the evaluation of newly registered circuits,
//   - as input provider, starts the provision of the node's inputs to executing
//
// It is the only place where side effects are decided.
func (r *Runner) reconcile() {
	for _, rc := range r.running {
		if r.isEvaluator(rc.md) && !rc.evalStarted {
			rc.evalStarted = true
			rc.executing = true
			r.emit(Event{EventType: Executing, Descriptor: rc.cd})
			r.wg.Add(1)
			go r.evaluate(rc)
		}
		if rc.executing && !rc.inputsScheduled && r.isParticipant(rc.md) {
			rc.inputsScheduled = true
			r.wg.Add(1)
			go r.provideInputs(rc)
		}
	}
	r.changed()
}

// evaluate evaluates the circuit rc as evaluator. It runs outside of the lock.
func (r *Runner) evaluate(rc *runningCircuit) {
	defer r.wg.Done()
	ctx := rc.ctx

	select {
	case r.evalSem <- struct{}{}:
		defer func() { <-r.evalSem }()
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

	r.Logf("evaluating circuit %s", rc.cd.HID())

	eval, err := r.evaluatorFor(ctx, rc.md.Keys)
	if err != nil {
		r.failLocal(rc, fmt.Errorf("cannot get evaluator: %w", err))
		return
	}

	rt := &circuitRuntime{r: r, rc: rc, eval: eval}
	if err := runCircuit(rc.circuit, rt); err != nil {
		r.failLocal(rc, err)
		return
	}

	outs := make([]helium.Operand, 0, len(rc.outputs))
	for name, oo := range rc.outputs {
		op, set := oo.Get()
		if !set {
			r.failLocal(rc, fmt.Errorf("output %s was not set by the circuit", name))
			return
		}
		outs = append(outs, op)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range outs {
		op := outs[i]
		r.operands[op.ID] = &op
	}
	if _, running := r.running[rc.cd.CircuitID]; !running {
		r.Logf("circuit %s terminated before its evaluation completed", rc.cd.HID())
		return
	}
	r.markCompleted(rc.cd)
	r.emit(Event{EventType: Completed, Descriptor: rc.cd})
	r.Logf("completed circuit %s", rc.cd.HID())
	r.changed()
}

// runCircuit runs the circuit's evaluation function, turning panics into errors.
func runCircuit(c helium.Circuit, rt helium.CircuitRuntime) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic during circuit evaluation: %v", r)
		}
	}()
	return c.Eval(rt)
}

// failLocal terminates a circuit evaluated by this node with a failure.
func (r *Runner) failLocal(rc *runningCircuit, cause error) {
	r.Logf("circuit %s failed: %s", rc.cd.HID(), cause)
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur, running := r.running[rc.cd.CircuitID]; !running || cur != rc {
		return // already terminated by an event
	}
	r.dropRunning(rc)
	r.markFailed(rc.cd)
	r.emit(Event{EventType: Failed, Descriptor: rc.cd})
	r.changed()
}

// evaluatorFor returns an evaluator initialized with the given keys.
func (r *Runner) evaluatorFor(ctx context.Context, keys helium.Keys) (helium.Evaluator, error) {
	var rlk *rlwe.RelinearizationKey
	if keys.Rlk {
		var err error
		if rlk, err = r.keys.GetRelinearizationKey(ctx); err != nil {
			return nil, err
		}
	}
	gks := make([]*rlwe.GaloisKey, 0, len(keys.GaloisEls))
	for _, galEl := range keys.GaloisEls {
		gk, err := r.keys.GetGaloisKey(ctx, galEl)
		if err != nil {
			return nil, err
		}
		gks = append(gks, gk)
	}
	return helium.NewEvaluator(r.sess.Params, rlwe.NewMemEvaluationKeySet(rlk, gks...)), nil
}

// provideInputs provides the node's inputs to circuit rc. It runs outside of the lock.
func (r *Runner) provideInputs(rc *runningCircuit) {
	defer r.wg.Done()
	ctx := rc.ctx
	select {
	case <-rc.done:
		return
	default:
	}
	ids := rc.md.InputsOf[r.self]
	if err := r.sendInputs(ctx, rc.md, ids); err != nil {
		r.Logf("error while providing inputs to %s: %s", rc.cd.HID(), err)
		return
	}
	r.Logf("provided %d input(s) to %s", len(ids), rc.cd.HID())
}

// ---- outputs

func (r *Runner) emit(ev Event) {
	r.outbox = append(r.outbox, ev)
	r.changed()
}

// changed signals the Run loop that the state has changed (non-blocking).
func (r *Runner) changed() {
	select {
	case r.notify <- struct{}{}:
	default:
	}
}

// publish sends the emitted events to the coordinator, outside of the lock.
func (r *Runner) publish(ctx context.Context, coord Coordinator) (err error) {
	r.mu.Lock()
	evs := r.outbox
	r.outbox = nil
	r.publishing = true
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.publishing = false
		r.wakeIdle()
		r.mu.Unlock()
	}()
	for _, ev := range evs {
		if err := coord.Publish(ctx, ev); err != nil {
			return fmt.Errorf("cannot publish %s: %w", ev, err)
		}
	}
	return nil
}

// Run connects the runner to a coordinator: the runner catches up with the past
// events, processes the live ones with HandleEvent and publishes its own events.
// The method returns when the coordinator closes the live channel, when publishing
// fails, or when the context is cancelled.
func (r *Runner) Run(ctx context.Context, coord Coordinator) (err error) {
	past, live, err := coord.Register(ctx)
	if err != nil {
		return fmt.Errorf("cannot register to coordinator: %w", err)
	}
	if err = r.Init(ctx, past); err != nil {
		return err
	}

	for done := false; !done; {
		select {
		case ev, more := <-live:
			if !more {
				done = true
				continue
			}
			if err = r.HandleEvent(ctx, ev); err != nil {
				done = true
			}
		case <-r.notify:
			if err = r.publish(ctx, coord); err != nil {
				done = true
			}
		case <-ctx.Done():
			err = ctx.Err()
			done = true
		}
	}
	r.wg.Wait()
	if perr := r.publish(ctx, coord); err == nil {
		err = perr
	}
	return err
}

// Logf logs a message with the runner's prefix.
func (r *Runner) Logf(msg string, v ...any) {
	log.Printf("%s | [circuits] %s\n", r.self, fmt.Sprintf(msg, v...))
}

// sortedIDs returns a sorted copy of the ids.
func sortedIDs(ids []helium.OperandID) []helium.OperandID {
	s := slices.Clone(ids)
	slices.Sort(s)
	return s
}
