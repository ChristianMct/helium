package protocols

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"sync"

	"github.com/ChristianMct/helium/coordinator"
	"github.com/ChristianMct/helium/sessions"
	"github.com/ChristianMct/helium/utils"
)

const (
	defaultEngineMaxParticipation = 8 // max number of concurrent share generations
	defaultEngineMaxProtoPerNode  = 8 // as aggregator, max number of concurrent protocols per participant
)

// ErrProtocolNotRunning is returned when an input (e.g., a share) refers to a
// protocol that is not currently running at this node.
var ErrProtocolNotRunning = errors.New("protocol is not running")

// Config is the configuration of an MHEMPC engine.
type Config struct {
	// MaxParticipation is the maximum number of shares generated concurrently by this node.
	MaxParticipation int
	// MaxProtoPerNode is, as aggregator, the maximum number of concurrent protocols a
	// given participant is selected in.
	MaxProtoPerNode int
}

// ShareTransport is the transport interface required by the MHEMPC engine.
// Shares and result queries are routed by the transport from the protocol
// descriptor (e.g., to pd.Aggregator), so that the engine is agnostic of
// the network topology.
type ShareTransport interface {
	// PutShare sends the node's share in protocol pd to the protocol's aggregator(s).
	PutShare(ctx context.Context, pd Descriptor, share Share) error
	// GetAggregationOutput queries the aggregated share of protocol pd from its aggregator(s).
	GetAggregationOutput(ctx context.Context, pd Descriptor) (Share, error)
}

// // ShareReceiver is the interface through which a transport delivers incoming
// // shares to the engine. It is implemented by MHEMPC.
// type ShareReceiver interface {
// 	HandleShare(ctx context.Context, share Share) error
// }

// KeySwitchInputProvider provides the inputs of the key-switching protocols (DEC, CKS, PCKS),
// for which the engine cannot derive the input on its own. It is called at both the
// participants and the aggregator, and must return the same ciphertext at all nodes.
type KeySwitchInputProvider func(ctx context.Context, pd Descriptor) (*KeySwitchInput, error)

// MHEMPC is the state of a node in the MHE-based MPC protocol, for a single session.
//
// The type is a state machine: its inputs are coordination events (HandleEvent),
// incoming shares (PutShare), peer connectivity changes (PeerConnected, PeerDisconnected)
// and protocol execution requests (RunSignature, RunDescriptor). Its outputs are
// coordination events (see Run) and shares sent through the ShareTransport.
// All inputs are processed synchronously under a single lock; the only asynchronous
// work is the share generation, which runs in a bounded pool of goroutines.
//
// For each protocol, the node's roles (aggregator, participant, key-switch receiver)
// are derived from the protocol descriptor only, so that the same type is used
// for helper and peer nodes, and by any node in a peer-to-peer setting.
//
// Completed protocols' results are held in a ResultBackend and are fetched lazily
// from the aggregator when not available locally (see GetAggregationOutput, GetOutput).
type MHEMPC struct {
	self    sessions.NodeID
	sess    *sessions.Session
	conf    Config
	trans   ShareTransport
	results ResultBackend
	ksInput KeySwitchInputProvider

	mu        sync.Mutex
	online    map[sessions.NodeID]utils.Set[ID] // connected peers -> running protocols they participate in
	queued    []*sigRequest                     // signatures to run as aggregator, waiting for participants
	running   map[ID]*runningProto
	completed map[ID]Descriptor
	bySig     map[string]Descriptor // signature string -> last completed descriptor
	failed    map[ID]Descriptor
	waiters   map[string][]chan Descriptor // AwaitCompleted waiters, by signature string
	outputs   map[ID]Output                // cache of finalized outputs
	outbox    []Event
	notify    chan struct{}

	genSem chan struct{}
	genWg  sync.WaitGroup
}

// sigRequest is a request to execute a signature as aggregator.
type sigRequest struct {
	ctx context.Context
	sig Signature
}

// runningProto is the engine state for a running protocol.
type runningProto struct {
	pd    Descriptor
	ctx   context.Context
	proto *Protocol   // aggregation state, nil if this node is not an aggregator for pd
	req   *sigRequest // the request that started this protocol, if any (aggregator only)

	shareScheduled bool          // participant: whether the share generation has been scheduled
	done           chan struct{} // closed when the protocol leaves the running state
}

// NewMHEMPC creates a new engine for the given node and session.
// The ksInput provider may be nil if the node never takes part in key-switching protocols.
func NewMHEMPC(self sessions.NodeID, sess *sessions.Session, conf Config, trans ShareTransport, results ResultBackend, ksInput KeySwitchInputProvider) (*MHEMPC, error) {
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
	if conf.MaxProtoPerNode <= 0 {
		conf.MaxProtoPerNode = defaultEngineMaxProtoPerNode
	}

	return &MHEMPC{
		self:      self,
		sess:      sess,
		conf:      conf,
		trans:     trans,
		results:   results,
		ksInput:   ksInput,
		online:    make(map[sessions.NodeID]utils.Set[ID]),
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
func (e *MHEMPC) NodeID() sessions.NodeID {
	return e.self
}

// Session returns the session of this engine.
func (e *MHEMPC) Session() *sessions.Session {
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
		return e.self == sessions.NodeID(pd.Signature.Args["target"])
	}
	return false
}

func (e *MHEMPC) fullThreshold() bool {
	return e.sess.Threshold == len(e.sess.Nodes)
}

// shareProviders returns the set of nodes expected to provide a share in pd:
// the participants, minus the receiver in the DEC protocol.
func shareProviders(pd Descriptor) utils.Set[sessions.NodeID] {
	exp := utils.NewSet(pd.Participants)
	if pd.Signature.Type == DEC {
		exp.Remove(sessions.NodeID(pd.Signature.Args["target"]))
	}
	return exp
}

// ---- state machine inputs

// Init initializes the engine state from a log of past coordination events
// (catch-up). The events are applied without side effects; the actions required
// by the resulting state (e.g., sending shares in still-running protocols) are
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
// this node is an aggregator. It implements ShareReceiver.
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

	e.completeLocal(rp)
	e.reconcile()
	return nil
}

// PeerConnected informs the engine that peer nid is now reachable. As aggregator,
// the engine only selects connected peers as participants.
func (e *MHEMPC) PeerConnected(nid sessions.NodeID) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, has := e.online[nid]; has {
		return
	}
	pids := utils.NewEmptySet[ID]()
	for pid, rp := range e.running {
		if rp.proto != nil && slices.Contains(rp.pd.Participants, nid) {
			pids.Add(pid)
		}
	}
	e.online[nid] = pids
	e.reconcile()
}

// PeerDisconnected informs the engine that peer nid is not reachable anymore.
// As aggregator, running protocols in which nid has not yet provided its share
// are failed (and retried if requested through RunSignature), unless the
// session is full-threshold, in which case nothing can be done but wait.
func (e *MHEMPC) PeerDisconnected(nid sessions.NodeID) {
	e.mu.Lock()
	defer e.mu.Unlock()

	pids, has := e.online[nid]
	if !has {
		return
	}
	delete(e.online, nid)

	if !e.fullThreshold() {
		for pid := range pids {
			rp, running := e.running[pid]
			if !running || rp.proto == nil || rp.proto.HasShareFrom(nid) {
				continue
			}
			e.Logf("node %s disconnected before providing its share, aborting protocol %s", nid, rp.pd.HID())
			e.failLocal(rp)
		}
	}
	e.reconcile()
}

// RunSignature requests the execution of a protocol with the given signature,
// with this node as aggregator. The method returns immediately: the protocol
// starts as soon as enough participants are connected, and is retried with
// other participants if it fails. Completion can be awaited with AwaitCompleted.
func (e *MHEMPC) RunSignature(ctx context.Context, sig Signature) error {
	if err := e.validateSignature(sig); err != nil {
		return fmt.Errorf("invalid signature %s: %w", sig, err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.queued = append(e.queued, &sigRequest{ctx: ctx, sig: sig})
	e.reconcile()
	return nil
}

// RunDescriptor starts the execution of the protocol described by pd, with this
// node as aggregator. Unlike RunSignature, the protocol is not retried on failure.
// The method returns an error if a participant is not connected (non-full-threshold
// sessions only) or if the protocol is already running or completed.
func (e *MHEMPC) RunDescriptor(ctx context.Context, pd Descriptor) error {
	if !e.isAggregator(pd) {
		return fmt.Errorf("node %s is not the aggregator of %s", e.self, pd.HID())
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	pid := pd.ID()
	if _, running := e.running[pid]; running {
		return fmt.Errorf("protocol %s is already running", pd.HID())
	}
	if _, completed := e.completed[pid]; completed {
		return fmt.Errorf("protocol %s is already completed", pd.HID())
	}
	if !e.fullThreshold() {
		for _, nid := range pd.Participants {
			if _, online := e.online[nid]; !online && nid != e.self {
				return fmt.Errorf("participant %s is not connected", nid)
			}
		}
	}
	if err := e.startAsAggregator(ctx, pd, nil); err != nil {
		return err
	}
	e.reconcile()
	return nil
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
		_, err := e.newRunning(ctx, pd, nil)
		return err
	case Completed:
		e.markCompleted(pd)
	case Failed:
		if rp, has := e.running[pid]; has {
			e.dropRunning(rp)
		}
		e.failed[pid] = pd
	case Executing:
	default:
		return fmt.Errorf("unknown event type: %d", ev.EventType)
	}
	return nil
}

// newRunning registers pd as running. If this node is an aggregator for pd, the
// aggregation state is created.
func (e *MHEMPC) newRunning(ctx context.Context, pd Descriptor, req *sigRequest) (*runningProto, error) {
	pid := pd.ID()
	rp := &runningProto{pd: pd, ctx: ctx, req: req, done: make(chan struct{})}
	if e.isAggregator(pd) {
		var err error
		if rp.proto, err = NewProtocol(pd, e.sess); err != nil {
			return nil, fmt.Errorf("cannot create protocol %s: %w", pd.HID(), err)
		}
		for _, nid := range pd.Participants {
			if pids, online := e.online[nid]; online {
				pids.Add(pid)
			}
		}
	}
	delete(e.failed, pid) // TODO: is this enough to just retry ?
	e.running[pid] = rp
	return rp, nil
}

// dropRunning removes rp from the running protocols.
func (e *MHEMPC) dropRunning(rp *runningProto) {
	pid := rp.pd.ID()
	delete(e.running, pid)
	for _, nid := range rp.pd.Participants {
		if pids, online := e.online[nid]; online {
			pids.Remove(pid)
		}
	}
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

// completeLocal terminates a protocol aggregated by this node, emitting the Completed
// event and starting the next round if the protocol was requested as part of a
// multi-round signature (RKG).
func (e *MHEMPC) completeLocal(rp *runningProto) {
	e.markCompleted(rp.pd)
	e.emit(Event{EventType: Completed, Descriptor: rp.pd})
	e.Logf("completed aggregation for %s", rp.pd.HID())

	if rp.req != nil && rp.req.sig.Type == RKG && rp.pd.Signature.Type == RKG1 {
		pd := Descriptor{Signature: rp.req.sig, Participants: rp.pd.Participants, Aggregator: e.self}
		if err := e.startAsAggregator(rp.req.ctx, pd, rp.req); err != nil {
			e.Logf("cannot start second round of %s: %s, retrying", rp.req.sig, err)
			e.queued = append(e.queued, rp.req)
		}
	}
}

// failLocal terminates a protocol aggregated by this node with a failure, emitting
// the Failed event and re-queuing the originating request, if any.
func (e *MHEMPC) failLocal(rp *runningProto) {
	e.dropRunning(rp)
	e.failed[rp.pd.ID()] = rp.pd
	e.emit(Event{EventType: Failed, Descriptor: rp.pd})
	if rp.req != nil {
		e.queued = append(e.queued, rp.req)
	}
}

// startAsAggregator registers pd as running with this node as aggregator and emits
// the Started event.
func (e *MHEMPC) startAsAggregator(ctx context.Context, pd Descriptor, req *sigRequest) error {
	if !e.isAggregator(pd) {
		return fmt.Errorf("node %s is not the aggregator of %s", e.self, pd.HID())
	}
	if _, err := e.newRunning(ctx, pd, req); err != nil {
		return err
	}
	e.emit(Event{EventType: Started, Descriptor: pd})
	e.Logf("started protocol %s", pd)
	return nil
}

// tryStart attempts to start the protocol for the request, returning whether it
// could be started. An error means the request cannot be satisfied and is dropped.
func (e *MHEMPC) tryStart(req *sigRequest) (bool, error) {
	sig := req.sig
	if sig.Type == RKG {
		sig = Signature{Type: RKG1, Args: sig.Args} // runs the first round first
	}

	parts, ok := e.selectParticipants(sig)
	if !ok {
		return false, nil
	}

	pd := Descriptor{Signature: sig, Participants: parts, Aggregator: e.self}
	pid := pd.ID()
	if _, running := e.running[pid]; running {
		return false, nil // waits for the running instance to terminate
	}
	if _, completed := e.completed[pid]; completed {
		// the exact same protocol has already completed, the request is satisfied.
		if req.sig.Type == RKG {
			if _, r2completed := e.completed[Descriptor{Signature: req.sig, Participants: parts, Aggregator: e.self}.ID()]; !r2completed {
				pd2 := Descriptor{Signature: req.sig, Participants: parts, Aggregator: e.self}
				return true, e.startAsAggregator(req.ctx, pd2, req)
			}
		}
		return true, nil
	}

	return true, e.startAsAggregator(req.ctx, pd, req)
}

// selectParticipants selects the participants for a protocol with signature sig,
// from the connected peers. It returns false if there are not enough available
// peers. In full-threshold sessions, all session nodes are selected.
func (e *MHEMPC) selectParticipants(sig Signature) ([]sessions.NodeID, bool) {
	selected := utils.NewEmptySet[sessions.NodeID]()
	if e.fullThreshold() {
		selected.Add(e.sess.Nodes...)
	} else {
		if sig.Type == DEC {
			if target := sessions.NodeID(sig.Args["target"]); e.sess.Contains(target) {
				selected.Add(target)
			}
		}
		available := utils.NewEmptySet[sessions.NodeID]()
		for nid, protos := range e.online {
			if e.sess.Contains(nid) && !selected.Contains(nid) && len(protos) < e.conf.MaxProtoPerNode {
				available.Add(nid)
			}
		}
		needed := e.sess.Threshold - len(selected)
		if len(available) < needed {
			return nil, false
		}
		selected.AddAll(utils.GetRandomSetOfSize(needed, available))
	}
	parts := selected.Elements()
	slices.Sort(parts)
	return parts, true
}

// reconcile derives the actions required by the current state:
//   - as aggregator, starts the queued requests for which enough participants are available,
//   - as participant, schedules the generation of the node's share in running protocols.
//
// It is the only place where side effects are decided.
func (e *MHEMPC) reconcile() {
	if len(e.queued) > 0 {
		var remaining []*sigRequest
		for _, req := range e.queued {
			started, err := e.tryStart(req)
			if err != nil {
				e.Logf("dropping request for %s: %s", req.sig, err)
				continue
			}
			if !started {
				remaining = append(remaining, req)
			}
		}
		e.queued = remaining
	}

	for _, rp := range e.running {
		if rp.shareScheduled || !e.isParticipant(rp.pd) || e.isKeySwitchReceiver(rp.pd) {
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

func (e *MHEMPC) validateSignature(sig Signature) error {
	switch sig.Type {
	case CKG, RTG, RKG, DEC:
	default:
		return fmt.Errorf("unsupported protocol type %s", sig.Type)
	}
	if sig.Type == DEC && len(sig.Args["target"]) == 0 {
		return fmt.Errorf("should provide argument: target")
	}
	_, err := newMHEProtocol(sig, *e.sess.Params.GetRLWEParameters())
	return err
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

// flush sends the emitted events to out. Events are dropped if out is nil.
func (e *MHEMPC) flush(out chan<- Event) {
	e.mu.Lock()
	evs := e.outbox
	e.outbox = nil
	e.mu.Unlock()
	if out == nil {
		return
	}
	for _, ev := range evs {
		out <- ev
	}
}

// aggregatorIdle returns whether the node has no pending work as aggregator.
func (e *MHEMPC) aggregatorIdle() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.queued) > 0 {
		return false
	}
	for _, rp := range e.running {
		if rp.proto != nil {
			return false
		}
	}
	return true
}

// Run connects the engine to a coordination channel: incoming events are processed
// with HandleEvent and emitted events are sent to the outgoing channel. The method
// returns when the incoming channel is closed and the node has no pending work as
// aggregator, or when the context is cancelled. It closes the outgoing channel
// before returning.
func (e *MHEMPC) Run(ctx context.Context, ch *coordinator.Channel[Event]) (err error) {
	incoming := ch.Incoming
	for done := false; !done; {
		select {
		case ev, more := <-incoming:
			if !more {
				incoming = nil
				done = e.aggregatorIdle()
				continue
			}
			if err = e.HandleEvent(ctx, ev); err != nil {
				done = true
			}
		case <-e.notify:
			e.flush(ch.Outgoing)
			done = incoming == nil && e.aggregatorIdle()
		case <-ctx.Done():
			err = ctx.Err()
			done = true
		}
	}
	e.genWg.Wait()
	e.flush(ch.Outgoing)
	if ch.Outgoing != nil {
		close(ch.Outgoing)
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
