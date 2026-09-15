package protocols

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"sync"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/coordinator"
	"github.com/ChristianMct/helium/utils"
)

const defaultCoordinatorMaxProtoPerNode = 8 // max number of concurrent protocols per participant

// ErrCoordinatorClosed is returned when interacting with a closed coordinator.
var ErrCoordinatorClosed = errors.New("coordinator is closed")

// Coordinator is the interface through which a Runner is driven.
// The coordinator decides which protocols are started (Started events) and
// which are aborted (Failed events); the runner executes them and publishes
// its progress (Executing, Completed events). All events form a single,
// causally-ordered log.
type Coordinator interface {
	// Register subscribes to the coordination events. It returns the events emitted
	// before the registration (past, for catching up), and a channel delivering the
	// following ones (live). The live channel is closed when the coordination ends.
	Register(ctx context.Context) (past []Event, live <-chan Event, err error)

	// Publish appends an event emitted by the runner (Executing, Completed) to the log.
	Publish(ctx context.Context, ev Event) error
}

// AggregationStatus is the interface a deciding coordinator requires from the runner,
// to determine whether a running protocol can survive the disconnection of a participant.
// It is implemented by Runner.
type AggregationStatus interface {
	// MissingShares returns the participants whose share has not yet been aggregated in pd.
	// The returned known is false if the runner neither runs nor has completed pd.
	MissingShares(pd Descriptor) (missing utils.Set[helium.NodeID], known bool)
}

// CoordinatorConfig is the configuration of a CentralCoordinator.
type CoordinatorConfig struct {
	// MaxProtoPerNode is the maximum number of concurrent protocols a given participant is selected in.
	MaxProtoPerNode int
}

// sigRequest is a request to execute a signature.
type sigRequest struct {
	ctx context.Context
	sig Signature
}

// scheduled is a protocol started by the coordinator and not yet terminated.
type scheduled struct {
	pd  Descriptor
	req *sigRequest // the originating request, if any (nil for RunDescriptor)
}

// CentralCoordinator is a Coordinator that owns the event log and takes the
// coordination decisions for the protocols aggregated by its node: it selects
// the participants among the connected peers, starts the requested protocols,
// aborts and retries them when a participant disconnects, and chains the rounds
// of multi-round protocols (RKG).
//
// It serves the log to any number of subscribers (the local runner and, through
// a transport, remote peers). This corresponds to the helper node in the
// helper-assisted setting; in a peer-to-peer setting, an instance would take
// the decisions for the protocols aggregated by its node.
type CentralCoordinator struct {
	self   helium.NodeID
	sess   *helium.Session
	conf   CoordinatorConfig
	status AggregationStatus

	mu      sync.Mutex
	log     *coordinator.Log[Event]
	closing bool // Close was called: the log closes once idle

	online    map[helium.NodeID]utils.Set[ID] // connected peers -> running protocols they participate in
	queued    []*sigRequest                   // requests waiting for available participants
	running   map[ID]*scheduled
	completed map[ID]Descriptor
	failed    map[ID]Descriptor
}

// NewCentralCoordinator creates a new coordinator for node self in the given session.
// The status is queried on peer disconnection; if nil, running protocols are
// considered to be missing the share of any disconnecting participant.
func NewCentralCoordinator(self helium.NodeID, sess *helium.Session, conf CoordinatorConfig, status AggregationStatus) (*CentralCoordinator, error) {
	if sess == nil {
		return nil, fmt.Errorf("session must not be nil")
	}
	if conf.MaxProtoPerNode <= 0 {
		conf.MaxProtoPerNode = defaultCoordinatorMaxProtoPerNode
	}
	c := &CentralCoordinator{
		self:      self,
		sess:      sess,
		conf:      conf,
		status:    status,
		log:       coordinator.NewLog[Event](),
		online:    make(map[helium.NodeID]utils.Set[ID]),
		running:   make(map[ID]*scheduled),
		completed: make(map[ID]Descriptor),
		failed:    make(map[ID]Descriptor),
	}
	return c, nil
}

// ---- Coordinator interface

// Register implements Coordinator. It can be called by the local runner and on behalf of remote peers.
func (c *CentralCoordinator) Register(ctx context.Context) (past []Event, live <-chan Event, err error) {
	past, live = c.log.Register(ctx)
	return past, live, nil
}

// Publish implements Coordinator. Runners may publish Executing and Completed events for
// protocols started by this coordinator. Events for unknown (e.g., already failed) protocols
// are ignored.
func (c *CentralCoordinator) Publish(_ context.Context, ev Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.log.Closed() {
		return ErrCoordinatorClosed
	}

	pid := ev.Descriptor.ID()
	s, running := c.running[pid]
	switch ev.EventType {
	case Executing:
		if !running {
			c.Logf("ignoring %s for unknown protocol", ev)
			return nil
		}
		c.append(ev)
	case Completed:
		if !running {
			c.Logf("ignoring %s for unknown protocol", ev)
			return nil
		}
		c.drop(s)
		c.completed[pid] = s.pd
		c.append(ev)
		c.Logf("completed protocol %s", s.pd.HID())
		if s.req != nil && s.req.sig.Type == RKG && s.pd.Signature.Type == RKG1 {
			pd2 := Descriptor{Signature: s.req.sig, Participants: s.pd.Participants, Aggregator: c.self}
			if err := c.start(pd2, s.req); err != nil {
				c.Logf("cannot start second round of %s: %s, retrying", s.req.sig, err)
				c.queued = append(c.queued, s.req)
			}
		}
		c.reconcile()
	default:
		return fmt.Errorf("runners may only publish %s and %s events, got %s", Executing, Completed, ev.EventType)
	}
	return nil
}

// ---- decisions

// RunSignature requests the execution of a protocol with the given signature, with this
// node as aggregator. The method returns immediately: the protocol starts as soon as
// enough participants are connected, and is retried with other participants if it fails.
func (c *CentralCoordinator) RunSignature(ctx context.Context, sig Signature) error {
	if err := c.validateSignature(sig); err != nil {
		return fmt.Errorf("invalid signature %s: %w", sig, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.log.Closed() {
		return ErrCoordinatorClosed
	}
	c.queued = append(c.queued, &sigRequest{ctx: ctx, sig: sig})
	c.reconcile()
	return nil
}

// RunDescriptor starts the protocol described by pd, with this node as aggregator.
// Unlike RunSignature, the protocol is not retried on failure. The method returns an
// error if a participant is not connected (non-full-threshold sessions only) or if
// the protocol is already running or completed.
func (c *CentralCoordinator) RunDescriptor(_ context.Context, pd Descriptor) error {
	if pd.Aggregator != c.self {
		return fmt.Errorf("node %s is not the aggregator of %s", c.self, pd.HID())
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.log.Closed() {
		return ErrCoordinatorClosed
	}
	pid := pd.ID()
	if _, running := c.running[pid]; running {
		return fmt.Errorf("protocol %s is already running", pd.HID())
	}
	if _, completed := c.completed[pid]; completed {
		return fmt.Errorf("protocol %s is already completed", pd.HID())
	}
	if !c.fullThreshold() {
		for _, nid := range pd.Participants {
			if _, online := c.online[nid]; !online && nid != c.self {
				return fmt.Errorf("participant %s is not connected", nid)
			}
		}
	}
	if err := c.start(pd, nil); err != nil {
		return err
	}
	c.reconcile()
	return nil
}

// PeerConnected informs the coordinator that peer nid is reachable and can be selected as participant.
func (c *CentralCoordinator) PeerConnected(nid helium.NodeID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, has := c.online[nid]; has {
		return
	}
	pids := utils.NewEmptySet[ID]()
	for pid, s := range c.running {
		if slices.Contains(s.pd.Participants, nid) {
			pids.Add(pid)
		}
	}
	c.online[nid] = pids
	c.reconcile()
}

// PeerDisconnected informs the coordinator that peer nid is not reachable anymore.
// Running protocols in which nid has not yet provided its share are failed (and retried
// if requested through RunSignature), unless the session is full-threshold, in which
// case nothing can be done but wait.
func (c *CentralCoordinator) PeerDisconnected(nid helium.NodeID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	pids, has := c.online[nid]
	if !has {
		return
	}
	delete(c.online, nid)

	if !c.fullThreshold() {
		for pid := range pids {
			s, running := c.running[pid]
			if !running {
				continue
			}
			var missing utils.Set[helium.NodeID]
			var known bool
			if c.status != nil {
				missing, known = c.status.MissingShares(s.pd)
			}
			if !known || missing.Contains(nid) {
				c.Logf("node %s disconnected before providing its share, aborting protocol %s", nid, s.pd.HID())
				c.fail(s)
			}
		}
	}
	c.reconcile()
}

// Restore records protocols that completed before this coordinator was created (e.g., loaded
// from persistent storage after a restart) by appending their Started, Executing and Completed
// events to the log.
func (c *CentralCoordinator) Restore(pds ...Descriptor) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, pd := range pds {
		c.completed[pd.ID()] = pd
		c.append(Event{EventType: Started, Descriptor: pd})
		c.append(Event{EventType: Executing, Descriptor: pd})
		c.append(Event{EventType: Completed, Descriptor: pd})
	}
}

// Close closes the coordination log once all requested protocols have terminated.
// Subscribers' live channels are closed at that point.
func (c *CentralCoordinator) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closing = true
	c.reconcile()
}

// Log returns a copy of the event log.
func (c *CentralCoordinator) Log() []Event {
	return c.log.Events()
}

// Logf logs a message with the coordinator's prefix.
func (c *CentralCoordinator) Logf(msg string, v ...any) {
	if !protocolLogging {
		return
	}
	log.Printf("%s | [coordinator] %s\n", c.self, fmt.Sprintf(msg, v...))
}

// ---- internals (caller holds c.mu)

func (c *CentralCoordinator) fullThreshold() bool {
	return c.sess.Threshold == len(c.sess.Nodes)
}

func (c *CentralCoordinator) append(ev Event) {
	if err := c.log.Append(ev); err != nil {
		c.Logf("cannot append %s: %s", ev, err)
	}
}

// start records pd as running and appends the Started event.
func (c *CentralCoordinator) start(pd Descriptor, req *sigRequest) error {
	pid := pd.ID()
	if _, running := c.running[pid]; running {
		return fmt.Errorf("protocol %s is already running", pd.HID())
	}
	s := &scheduled{pd: pd, req: req}
	c.running[pid] = s
	delete(c.failed, pid)
	for _, nid := range pd.Participants {
		if pids, online := c.online[nid]; online {
			pids.Add(pid)
		}
	}
	c.append(Event{EventType: Started, Descriptor: pd})
	c.Logf("started protocol %s", pd)
	return nil
}

// drop removes s from the running protocols, freeing its participants.
func (c *CentralCoordinator) drop(s *scheduled) {
	pid := s.pd.ID()
	delete(c.running, pid)
	for _, nid := range s.pd.Participants {
		if pids, online := c.online[nid]; online {
			pids.Remove(pid)
		}
	}
}

// fail terminates s with a failure and re-queues its request, if any.
func (c *CentralCoordinator) fail(s *scheduled) {
	c.drop(s)
	c.failed[s.pd.ID()] = s.pd
	c.append(Event{EventType: Failed, Descriptor: s.pd})
	if s.req != nil {
		c.queued = append(c.queued, s.req)
	}
}

// tryStart attempts to start the protocol for req, returning whether it could be started.
// An error means the request cannot be satisfied and is dropped.
func (c *CentralCoordinator) tryStart(req *sigRequest) (bool, error) {
	sig := req.sig
	if sig.Type == RKG {
		sig = Signature{Type: RKG1, Args: sig.Args} // runs the first round first
	}

	parts, ok := c.selectParticipants(sig)
	if !ok {
		return false, nil
	}

	pd := Descriptor{Signature: sig, Participants: parts, Aggregator: c.self}
	if _, running := c.running[pd.ID()]; running {
		return false, nil // waits for the running instance to terminate
	}
	if _, completed := c.completed[pd.ID()]; completed {
		// the exact same protocol has already completed: the request is satisfied,
		// unless it is a multi-round request whose next round is still to be run.
		if req.sig.Type == RKG {
			pd2 := Descriptor{Signature: req.sig, Participants: parts, Aggregator: c.self}
			if _, r2running := c.running[pd2.ID()]; r2running {
				return false, nil
			}
			if _, r2completed := c.completed[pd2.ID()]; !r2completed {
				return true, c.start(pd2, req)
			}
		}
		return true, nil
	}
	return true, c.start(pd, req)
}

// selectParticipants selects the participants for a protocol with signature sig among the
// connected peers. It returns false if there are not enough available peers. In full-threshold
// sessions, all session nodes are selected.
func (c *CentralCoordinator) selectParticipants(sig Signature) ([]helium.NodeID, bool) {
	selected := utils.NewEmptySet[helium.NodeID]()
	if c.fullThreshold() {
		selected.Add(c.sess.Nodes...)
	} else {
		if sig.Type == DEC {
			if target := helium.NodeID(sig.Args["target"]); c.sess.Contains(target) {
				selected.Add(target)
			}
		}
		available := utils.NewEmptySet[helium.NodeID]()
		for nid, protos := range c.online {
			if c.sess.Contains(nid) && !selected.Contains(nid) && len(protos) < c.conf.MaxProtoPerNode {
				available.Add(nid)
			}
		}
		needed := c.sess.Threshold - len(selected)
		if len(available) < needed {
			return nil, false
		}
		selected.AddAll(utils.GetRandomSetOfSize(needed, available))
	}
	parts := selected.Elements()
	slices.Sort(parts)
	return parts, true
}

// reconcile starts the queued requests for which participants are available, and
// closes the log if Close was called and no protocol is queued or running.
func (c *CentralCoordinator) reconcile() {
	if len(c.queued) > 0 {
		var remaining []*sigRequest
		for _, req := range c.queued {
			started, err := c.tryStart(req)
			if err != nil {
				c.Logf("dropping request for %s: %s", req.sig, err)
				continue
			}
			if !started {
				remaining = append(remaining, req)
			}
		}
		c.queued = remaining
	}

	if c.closing && !c.log.Closed() && len(c.queued) == 0 && len(c.running) == 0 {
		c.log.Close()
		c.Logf("log closed")
	}
}

func (c *CentralCoordinator) validateSignature(sig Signature) error {
	switch sig.Type {
	case CKG, RTG, RKG, DEC:
	default:
		return fmt.Errorf("unsupported protocol type %s", sig.Type)
	}
	if sig.Type == DEC && len(sig.Args["target"]) == 0 {
		return fmt.Errorf("should provide argument: target")
	}
	_, err := newMHEProtocol(sig, *c.sess.Params.GetRLWEParameters())
	return err
}
