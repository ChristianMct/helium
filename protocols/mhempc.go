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

const defaultEngineMaxParticipation = 8 // max number of concurrent share generations

// ErrProtocolNotRunning is returned when an input (e.g., a share) refers to a
// protocol that is not currently running at this node.
var ErrProtocolNotRunning = errors.New("protocol is not running")

// Config is the configuration of an MHEMPC engine.
type Config struct {
	// MaxParticipation is the maximum number of shares generated concurrently by this node.
	MaxParticipation int
}

// ShareTransport is the transport interface required by the MHEMPC engine.
// Shares and result queries are routed by the transport from the protocol
// descriptor (e.g., to pd.Aggregator), so that the engine is agnostic of
// the network topology. Incoming shares are delivered to the engine by
// calling its HandleShare method.
type ShareTransport interface {
	// PutShare sends the node's share in protocol pd to the protocol's aggregator(s).
	PutShare(ctx context.Context, pd Descriptor, share Share) error
	// GetAggregationOutput queries the aggregated share of protocol pd from its aggregator(s).
	GetAggregationOutput(ctx context.Context, pd Descriptor) (Share, error)
}

// KeySwitchInputProvider provides the inputs of the key-switching protocols (DEC, CKS, PCKS),
// for which the engine cannot derive the input on its own. It is called at both the
// participants and the aggregator, and must return the same ciphertext at all nodes.
type KeySwitchInputProvider func(ctx context.Context, pd Descriptor) (*KeySwitchInput, error)

// MHEMPC is the state of a node in the MHE-based MPC protocol, for a single session.
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
// The engine takes no coordination decision (see CentralCoordinator).
//
// Completed protocols' results are held in a ResultBackend and are fetched lazily
// from the aggregator when not available locally (see GetAggregationOutput, GetOutput).
type MHEMPC struct {
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

// runningProto is the engine state for a running protocol.
type runningProto struct {
	pd    Descriptor
	ctx   context.Context
	proto *Protocol // aggregation state, nil if this node is not an aggregator for pd

	executing      bool          // whether the aggregator is ready to receive shares
	shareScheduled bool          // participant: whether the share generation has been scheduled
	done           chan struct{} // closed when the protocol leaves the running state
}

// NewMHEMPC creates a new engine for the given node and session.
// The ksInput provider may be nil if the node never takes part in key-switching protocols.
func NewMHEMPC(self helium.NodeID, sess *helium.Session, conf Config, trans ShareTransport, results ResultBackend, ksInput KeySwitchInputProvider) (*MHEMPC, error) {
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
		conf.MaxParticipation = defaultEngineMaxParticipation
	}

	return &MHEMPC{
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

// NodeID returns the id of the node running this engine.
func (e *MHEMPC) NodeID() helium.NodeID {
	return e.self
}

// Session returns the session of this engine.
func (e *MHEMPC) Session() *helium.Session {
	return e.sess
}

// ---- roles

func (e *MHEMPC) isAggregator(pd Descriptor) bool {
	return pd.Aggregator == e.self
}

func (e *MHEMPC) isParticipant(pd Descriptor) bool {
	return slices.Contains(pd.Participants, e.self)
}

func (e *MHEMPC) isKeySwitchReceiver(pd Descriptor) bool {
	switch pd.Signature.Type {
	case DEC, PCKS:
		return e.self == helium.NodeID(pd.Signature.Args["target"])
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

// Init initializes the engine state from a log of past coordination events
// (catch-up). The events are applied without side effects; the actions required
// by the resulting state (e.g., sending shares in still-executing protocols) are
// then taken at once.
func (e *MHEMPC) Init(ctx context.Context, events []Event) error {
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
// duplicated events, and tolerates receiving events about protocols in which
// the node has no role.
func (e *MHEMPC) HandleEvent(ctx context.Context, ev Event) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.apply(ctx, ev); err != nil {
		return err
	}
	e.reconcile()
	return nil
}

// HandleShare processes a share sent by a participant in a protocol for which
// this node is an aggregator. It returns ErrProtocolNotRunning if the protocol
// is not running at this node.
func (e *MHEMPC) HandleShare(ctx context.Context, share Share) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	rp, has := e.running[share.ProtocolID]
	if !has {
		return fmt.Errorf("%w: %s", ErrProtocolNotRunning, share.ProtocolID)
	}
	if rp.proto == nil {
		return fmt.Errorf("node %s is not an aggregator for protocol %s", e.self, rp.pd.HID())
	}

	complete, err := rp.proto.PutShare(share)
	if err != nil {
		return fmt.Errorf("cannot aggregate share from %v in %s: %w", share.From.Elements(), rp.pd.HID(), err)
	}
	if !complete {
		return nil
	}

	if err := e.results.Put(rp.pd, rp.proto.AggregatedShare()); err != nil {
		return fmt.Errorf("cannot store aggregation output for %s: %w", rp.pd.HID(), err)
	}

	e.markCompleted(rp.pd)
	e.emit(Event{EventType: Completed, Descriptor: rp.pd})
	e.Logf("completed aggregation for %s", rp.pd.HID())
	e.reconcile()
	return nil
}

// MissingShares implements AggregationStatus.
func (e *MHEMPC) MissingShares(pd Descriptor) (missing utils.Set[helium.NodeID], known bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	pid := pd.ID()
	if rp, has := e.running[pid]; has && rp.proto != nil {
		return rp.proto.Missing(), true
	}
	if _, has := e.completed[pid]; has {
		return utils.NewEmptySet[helium.NodeID](), true
	}
	return nil, false
}

// ---- state transitions (caller holds e.mu)

// apply applies a coordination event to the state, without side effects.
func (e *MHEMPC) apply(ctx context.Context, ev Event) error {
	pd := ev.Descriptor
	pid := pd.ID()
	switch ev.EventType {
	case Started:
		if _, has := e.completed[pid]; has {
			return nil
		}
		if _, has := e.running[pid]; has {
			return nil
		}
		rp := &runningProto{pd: pd, ctx: ctx, done: make(chan struct{})}
		if e.isAggregator(pd) {
			var err error
			if rp.proto, err = NewProtocol(pd, e.sess); err != nil {
				return fmt.Errorf("cannot create protocol %s: %w", pd.HID(), err)
			}
		}
		delete(e.failed, pid)
		e.running[pid] = rp
	case Executing:
		if rp, has := e.running[pid]; has {
			rp.executing = true
		}
	case Completed:
		e.markCompleted(pd)
	case Failed:
		if rp, has := e.running[pid]; has {
			e.dropRunning(rp)
		}
		e.failed[pid] = pd
	default:
		return fmt.Errorf("unknown event type: %d", ev.EventType)
	}
	return nil
}

// dropRunning removes rp from the running protocols.
func (e *MHEMPC) dropRunning(rp *runningProto) {
	delete(e.running, rp.pd.ID())
	close(rp.done)
}

// markCompleted records pd as completed and wakes up the waiters on its signature.
func (e *MHEMPC) markCompleted(pd Descriptor) {
	pid := pd.ID()
	if rp, has := e.running[pid]; has {
		e.dropRunning(rp)
	}
	delete(e.failed, pid)
	e.completed[pid] = pd
	key := pd.Signature.String()
	e.bySig[key] = pd
	for _, w := range e.waiters[key] {
		w <- pd
	}
	delete(e.waiters, key)
}

// reconcile derives the actions required by the current state:
//   - as aggregator, publishes Executing for newly registered protocols,
//   - as participant, schedules the generation of the node's share in executing protocols.
//
// It is the only place where side effects are decided.
func (e *MHEMPC) reconcile() {
	for _, rp := range e.running {
		if rp.proto != nil && !rp.executing {
			rp.executing = true
			e.emit(Event{EventType: Executing, Descriptor: rp.pd})
		}
		if !rp.executing || rp.shareScheduled || !e.isParticipant(rp.pd) || e.isKeySwitchReceiver(rp.pd) {
			continue
		}
		rp.shareScheduled = true
		e.genWg.Add(1)
		go e.generateShare(rp)
	}
	e.changed()
}

// generateShare generates and sends the node's share for rp. It runs outside of the lock.
func (e *MHEMPC) generateShare(rp *runningProto) {
	defer e.genWg.Done()
	ctx := rp.ctx

	select {
	case e.genSem <- struct{}{}:
		defer func() { <-e.genSem }()
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
	if err := e.sendShare(ctx, pd); err != nil {
		e.Logf("error while participating in %s: %s", pd.HID(), err)
		return
	}
	e.Logf("completed participation for %s", pd.HID())
}

func (e *MHEMPC) sendShare(ctx context.Context, pd Descriptor) error {
	proto, err := NewProtocol(pd, e.sess)
	if err != nil {
		return err
	}
	sk, err := e.sess.GetSecretKeyForGroup(pd.Participants)
	if err != nil {
		return fmt.Errorf("cannot get secret key: %w", err)
	}
	in, err := e.getInput(ctx, pd)
	if err != nil {
		return fmt.Errorf("cannot get input: %w", err)
	}
	share := proto.AllocateShare()
	if err := proto.GenShare(sk, in, &share); err != nil {
		return fmt.Errorf("cannot generate share: %w", err)
	}
	if err := e.trans.PutShare(ctx, pd, share); err != nil {
		return fmt.Errorf("cannot send share: %w", err)
	}
	return nil
}

// ---- outputs

func (e *MHEMPC) emit(ev Event) {
	e.outbox = append(e.outbox, ev)
	e.changed()
}

// changed signals the Run loop that the state has changed (non-blocking).
func (e *MHEMPC) changed() {
	select {
	case e.notify <- struct{}{}:
	default:
	}
}

// publish sends the emitted events to the coordinator, outside of the lock.
func (e *MHEMPC) publish(ctx context.Context, coord Coordinator) error {
	e.mu.Lock()
	evs := e.outbox
	e.outbox = nil
	e.mu.Unlock()
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
func (e *MHEMPC) Run(ctx context.Context, coord Coordinator) (err error) {
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
	e.genWg.Wait()
	if perr := e.publish(ctx, coord); err == nil {
		err = perr
	}
	return err
}

// Logf logs a message with the engine's prefix.
func (e *MHEMPC) Logf(msg string, v ...any) {
	if !protocolLogging {
		return
	}
	log.Printf("%s | [mhempc] %s\n", e.self, fmt.Sprintf(msg, v...))
}
