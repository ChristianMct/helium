package protocols

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"sync"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/utils"
)

const defaultMaxParticipation = 8 // max number of concurrent share generations

// ErrProtocolNotRunning is returned when an input (e.g., a share) refers to a
// protocol that is not currently running at this node.
var ErrProtocolNotRunning = errors.New("protocol is not running")

// Config is the configuration of a Runner.
type Config struct {
	// MaxParticipation is the maximum number of shares generated concurrently by this node.
	MaxParticipation int
}

// ShareTransport is the transport interface required by a Runner.
// Shares and result queries are routed by the transport from the protocol
// descriptor (e.g., to pd.Aggregator), so that the runner is agnostic of
// the network topology. Incoming shares are delivered to the runner by
// calling its HandleShare method.
type ShareTransport interface {
	// PutShare sends the node's share in protocol pd to the protocol's aggregator(s).
	PutShare(ctx context.Context, pd Descriptor, share Share) error
	// GetAggregationOutput queries the aggregated share of protocol pd from its aggregator(s).
	GetAggregationOutput(ctx context.Context, pd Descriptor) (Share, error)
}

// KeySwitchInputProvider provides the inputs of the key-switching protocols (DEC, CKS, PCKS),
// for which the runner cannot derive the input on its own. It is called at both the
// participants and the aggregator, and must return the same ciphertext at all nodes.
type KeySwitchInputProvider func(ctx context.Context, pd Descriptor) (*KeySwitchInput, error)

// Runner is the state of a node in the protocols of a session. It is the sibling of
// circuits.Runner, which runs the session's circuit evaluations.
//
// The type is a state machine driven by the coordination events of a Coordinator
// (HandleEvent) and by incoming shares (HandleShare). It executes the protocols
// described by the events, in the roles the descriptors assign to the node, and
// publishes its progress back to the coordinator:
//   - Started: the protocol is registered; as aggregator, the aggregation state is
//     created and an Executing event is published,
//   - Executing: as participant, the node's share is generated and sent,
//   - Completed: the protocol result is available (published by the aggregator),
//   - Failed: the protocol is dropped.
//
// All inputs are processed synchronously under a single lock; the only asynchronous
// work is the share generation, which runs in a bounded pool of goroutines.
// The runner takes no coordination decision (see CentralCoordinator).
//
// Completed protocols' results are held in a ResultBackend and are fetched lazily
// from the aggregator when not available locally (see GetAggregationOutput, GetOutput).
type Runner struct {
	self    helium.NodeID
	sess    *helium.Session
	conf    Config
	trans   ShareTransport
	results ResultBackend
	ksInput KeySwitchInputProvider

	mu        sync.Mutex
	running   map[ID]*runningProto
	completed map[ID]Descriptor
	bySig     map[string]Descriptor // signature string -> last completed descriptor
	failed    map[ID]Descriptor
	waiters   map[string][]chan Descriptor // AwaitCompleted waiters, by signature string
	outputs   map[ID]Output                // cache of finalized outputs
	outbox    []Event                      // events to publish
	notify    chan struct{}

	genSem chan struct{}
	genWg  sync.WaitGroup
}

// runningProto is the runner state for a running protocol.
type runningProto struct {
	pd    Descriptor
	ctx   context.Context
	proto *Protocol // aggregation state, nil if this node is not an aggregator for pd

	executing      bool          // whether the aggregator is ready to receive shares
	shareScheduled bool          // participant: whether the share generation has been scheduled
	done           chan struct{} // closed when the protocol leaves the running state
}

// NewRunner creates a new runner for the given node and session.
// The ksInput provider may be nil if the node never takes part in key-switching protocols.
func NewRunner(self helium.NodeID, sess *helium.Session, conf Config, trans ShareTransport, results ResultBackend, ksInput KeySwitchInputProvider) (*Runner, error) {
	if sess == nil {
		return nil, fmt.Errorf("session must not be nil")
	}
	if trans == nil {
		return nil, fmt.Errorf("transport must not be nil")
	}
	if results == nil {
		return nil, fmt.Errorf("result backend must not be nil")
	}
	if conf.MaxParticipation <= 0 {
		conf.MaxParticipation = defaultMaxParticipation
	}

	return &Runner{
		self:      self,
		sess:      sess,
		conf:      conf,
		trans:     trans,
		results:   results,
		ksInput:   ksInput,
		running:   make(map[ID]*runningProto),
		completed: make(map[ID]Descriptor),
		bySig:     make(map[string]Descriptor),
		failed:    make(map[ID]Descriptor),
		waiters:   make(map[string][]chan Descriptor),
		outputs:   make(map[ID]Output),
		notify:    make(chan struct{}, 1),
		genSem:    make(chan struct{}, conf.MaxParticipation),
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

// ---- roles

func (r *Runner) isAggregator(pd Descriptor) bool {
	return pd.Aggregator == r.self
}

func (r *Runner) isParticipant(pd Descriptor) bool {
	return slices.Contains(pd.Participants, r.self)
}

func (r *Runner) isKeySwitchReceiver(pd Descriptor) bool {
	switch pd.Signature.Type {
	case DEC, PCKS:
		return r.self == helium.NodeID(pd.Signature.Args["target"])
	}
	return false
}

// shareProviders returns the set of nodes expected to provide a share in pd:
// the participants, minus the receiver in the DEC protocol.
func shareProviders(pd Descriptor) utils.Set[helium.NodeID] {
	exp := utils.NewSet(pd.Participants)
	if pd.Signature.Type == DEC {
		exp.Remove(helium.NodeID(pd.Signature.Args["target"]))
	}
	return exp
}

// ---- state machine inputs

// Init initializes the runner state from a log of past coordination events
// (catch-up). The events are applied without side effects; the actions required
// by the resulting state (e.g., sending shares in still-executing protocols) are
// then taken at once.
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
// duplicated events, and tolerates receiving events about protocols in which
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

// HandleShare processes a share sent by a participant in a protocol for which
// this node is an aggregator. It returns ErrProtocolNotRunning if the protocol
// is not running at this node.
func (r *Runner) HandleShare(ctx context.Context, share Share) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	rp, has := r.running[share.ProtocolID]
	if !has {
		return fmt.Errorf("%w: %s", ErrProtocolNotRunning, share.ProtocolID)
	}
	if rp.proto == nil {
		return fmt.Errorf("node %s is not an aggregator for protocol %s", r.self, rp.pd.HID())
	}

	complete, err := rp.proto.PutShare(share)
	if err != nil {
		return fmt.Errorf("cannot aggregate share from %v in %s: %w", share.From.Elements(), rp.pd.HID(), err)
	}
	if !complete {
		return nil
	}

	if err := r.results.Put(rp.pd, rp.proto.AggregatedShare()); err != nil {
		return fmt.Errorf("cannot store aggregation output for %s: %w", rp.pd.HID(), err)
	}

	r.markCompleted(rp.pd)
	r.emit(Event{EventType: Completed, Descriptor: rp.pd})
	r.Logf("completed aggregation for %s", rp.pd.HID())
	r.reconcile()
	return nil
}

// MissingShares implements AggregationStatus.
func (r *Runner) MissingShares(pd Descriptor) (missing utils.Set[helium.NodeID], known bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pid := pd.ID()
	if rp, has := r.running[pid]; has && rp.proto != nil {
		return rp.proto.Missing(), true
	}
	if _, has := r.completed[pid]; has {
		return utils.NewEmptySet[helium.NodeID](), true
	}
	return nil, false
}

// ---- state transitions (caller holds r.mu)

// apply applies a coordination event to the state, without side effects.
func (r *Runner) apply(ctx context.Context, ev Event) error {
	pd := ev.Descriptor
	pid := pd.ID()
	switch ev.EventType {
	case Started:
		if _, has := r.completed[pid]; has {
			return nil
		}
		if _, has := r.running[pid]; has {
			return nil
		}
		rp := &runningProto{pd: pd, ctx: ctx, done: make(chan struct{})}
		if r.isAggregator(pd) {
			var err error
			if rp.proto, err = NewProtocol(pd, r.sess); err != nil {
				return fmt.Errorf("cannot create protocol %s: %w", pd.HID(), err)
			}
		}
		delete(r.failed, pid)
		r.running[pid] = rp
	case Executing:
		if rp, has := r.running[pid]; has {
			rp.executing = true
		}
	case Completed:
		r.markCompleted(pd)
	case Failed:
		if rp, has := r.running[pid]; has {
			r.dropRunning(rp)
		}
		r.failed[pid] = pd
	default:
		return fmt.Errorf("unknown event type: %d", ev.EventType)
	}
	return nil
}

// dropRunning removes rp from the running protocols.
func (r *Runner) dropRunning(rp *runningProto) {
	delete(r.running, rp.pd.ID())
	close(rp.done)
}

// markCompleted records pd as completed and wakes up the waiters on its signature.
func (r *Runner) markCompleted(pd Descriptor) {
	pid := pd.ID()
	if rp, has := r.running[pid]; has {
		r.dropRunning(rp)
	}
	delete(r.failed, pid)
	r.completed[pid] = pd
	key := pd.Signature.String()
	r.bySig[key] = pd
	for _, w := range r.waiters[key] {
		w <- pd
	}
	delete(r.waiters, key)
}

// reconcile derives the actions required by the current state:
//   - as aggregator, publishes Executing for newly registered protocols,
//   - as participant, schedules the generation of the node's share in executing protocols.
//
// It is the only place where side effects are decided.
func (r *Runner) reconcile() {
	for _, rp := range r.running {
		if rp.proto != nil && !rp.executing {
			rp.executing = true
			r.emit(Event{EventType: Executing, Descriptor: rp.pd})
		}
		if !rp.executing || rp.shareScheduled || !r.isParticipant(rp.pd) || r.isKeySwitchReceiver(rp.pd) {
			continue
		}
		rp.shareScheduled = true
		r.genWg.Add(1)
		go r.generateShare(rp)
	}
	r.changed()
}

// generateShare generates and sends the node's share for rp. It runs outside of the lock.
func (r *Runner) generateShare(rp *runningProto) {
	defer r.genWg.Done()
	ctx := rp.ctx

	select {
	case r.genSem <- struct{}{}:
		defer func() { <-r.genSem }()
	case <-rp.done:
		return
	case <-ctx.Done():
		return
	}

	select {
	case <-rp.done:
		return // the protocol terminated before we could take part
	default:
	}

	pd := rp.pd
	if err := r.sendShare(ctx, pd); err != nil {
		r.Logf("error while participating in %s: %s", pd.HID(), err)
		return
	}
	r.Logf("completed participation for %s", pd.HID())
}

func (r *Runner) sendShare(ctx context.Context, pd Descriptor) error {
	proto, err := NewProtocol(pd, r.sess)
	if err != nil {
		return err
	}
	sk, err := r.sess.GetSecretKeyForGroup(pd.Participants)
	if err != nil {
		return fmt.Errorf("cannot get secret key: %w", err)
	}
	in, err := r.getInput(ctx, pd)
	if err != nil {
		return fmt.Errorf("cannot get input: %w", err)
	}
	share := proto.AllocateShare()
	if err := proto.GenShare(sk, in, &share); err != nil {
		return fmt.Errorf("cannot generate share: %w", err)
	}
	if err := r.trans.PutShare(ctx, pd, share); err != nil {
		return fmt.Errorf("cannot send share: %w", err)
	}
	return nil
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
func (r *Runner) publish(ctx context.Context, coord Coordinator) error {
	r.mu.Lock()
	evs := r.outbox
	r.outbox = nil
	r.mu.Unlock()
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
	r.genWg.Wait()
	if perr := r.publish(ctx, coord); err == nil {
		err = perr
	}
	return err
}

// Logf logs a message with the runner's prefix.
func (r *Runner) Logf(msg string, v ...any) {
	if !protocolLogging {
		return
	}
	log.Printf("%s | [protocols] %s\n", r.self, fmt.Sprintf(msg, v...))
}
