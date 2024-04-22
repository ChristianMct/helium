package protocols

import (
	"context"
	"fmt"
	"log"
	"slices"
	"sync"

	"github.com/ChristianMct/helium/coordinator"
	"github.com/ChristianMct/helium/sessions"
	"github.com/ChristianMct/helium/utils"
	"golang.org/x/sync/errgroup"
)

const (
	defaultSigQueueSize     = 256 // as coordinator, capacity of the pending signature channel
	defaultMaxParticipation = 8   // as participant, max number of parallel proto participation
	defaultMaxAggregation   = 8   // as aggregator, max number of parallel proto aggrations
	defaultMaxProtoPerNode  = 8   // as coordinator, max number of parallel proto per participant
)

// Executor is a type for executing protocols.
// It enables concurrent execution of protocols and handles both running the
// protocol as a participant and as an aggregator/coordinator.
// As a participant, the executor will generate the share and send it to the
// aggregator. As an aggregator/coordinator, the executor will decide on the
// participant list based on the regsitered nodes, and perform the aggregation.
type Executor struct {
	config ExecutorConfig
	self   sessions.NodeID

	sessProvider  sessions.Provider
	transport     Transport
	upstream      *coordinator.Channel[Event]
	inputProvider InputProvider

	// node tracking
	connectedNodes     map[sessions.NodeID]utils.Set[ID]
	connectedNodesMu   sync.RWMutex
	connectedNodesCond sync.Cond

	// protocol tracking
	queuedSig chan struct {
		sig Signature
		rec AggregationOutputReceiver
		ctx context.Context
	}

	queuedPart chan struct {
		pd  Descriptor
		ctx context.Context
	}

	runningProtoMu sync.RWMutex
	runningProtos  map[ID]struct {
		pd           Descriptor
		incoming     chan Share
		disconnected chan sessions.NodeID
	}

	completedProtos []Descriptor
}

// ExecutorConfig is the configuration for the executor.
type ExecutorConfig struct {
	// As coordinator
	// SigQueueSize is the size of the signature queue. If the queue is full the RunSignature method blocks.
	SigQueueSize int
	// MaxProtoPerNode is the maximum number of parallel proto participation per registered node.
	MaxProtoPerNode int

	// as aggregator
	// MaxAggregation is the maximum number of parallel proto aggrations for this executor.
	MaxAggregation int

	// as participant
	// MaxParticipation is the maximum number of parallel proto participation for this executor.
	MaxParticipation int
}

// Transport defines the transport interface required for the executor.
type Transport interface {
	OutgoingShares() chan<- Share
	IncomingShares() <-chan Share
}

// InputProvider is the interface the provision of protocol inputs. It is called
// by the executor to get the CRP (CKG, RTG, RKG) and ciphertexts (DEC, CKS, PCKS)
// for the  protocols.
type InputProvider func(ctx context.Context, pd Descriptor) (Input, error)

// AggregationOutputReceiver is the interface for receiving aggregation outputs
// from the executor. These types are registered as callbacks when requesting
// the execution of a protocol.
type AggregationOutputReceiver func(context.Context, AggregationOutput) error

// Event is a type for protocol-execution-related events.
type Event struct {
	EventType
	Descriptor
}

// EventType defines the type of protocol-execution-related events.
type EventType int8

const (
	// Completed is the event type for a completed protocol.
	Completed EventType = iota
	// Started is the event type for a started protocol.
	Started
	// Executing is the event type for a protocol that is currently executing. It is currently not used.
	Executing
	// Failed is the event type for a protocol that has failed.
	Failed
)

var evtypeToString = []string{"COMPLETED", "STARTED", "EXECUTING", "FAILED"}

// String returns the string representation of the event type.
func (t EventType) String() string {
	if int(t) > len(evtypeToString) {
		t = 0
	}
	return evtypeToString[t]
}

// String returns the string representation of the event.
func (ev Event) String() string {
	return fmt.Sprintf("%s: %s", ev.EventType, ev.Descriptor.HID())
}

// IsSetupEvent returns true if the event is a setup-related event.
func (ev Event) IsSetupEvent() bool {
	return ev.Signature.Type.IsSetup()
}

// IsComputeEvent returns true if the event is a compute-related event.
func (ev Event) IsComputeEvent() bool {
	return ev.Signature.Type.IsCompute()
}

// NewExectutor creates a new executor.
func NewExectutor(config ExecutorConfig, ownID sessions.NodeID, sessProv sessions.Provider, upstream *coordinator.Channel[Event], ip InputProvider) (*Executor, error) {
	s := new(Executor)
	s.config = config
	if s.config.SigQueueSize == 0 {
		s.config.SigQueueSize = defaultSigQueueSize
	}
	if s.config.MaxProtoPerNode == 0 {
		s.config.MaxProtoPerNode = defaultMaxProtoPerNode
	}
	if s.config.MaxAggregation == 0 {
		s.config.MaxAggregation = defaultMaxAggregation
	}
	if s.config.MaxParticipation == 0 {
		s.config.MaxParticipation = defaultMaxParticipation
	}

	s.self = ownID
	s.sessProvider = sessProv

	// TODO Register in Run
	s.upstream = upstream

	s.inputProvider = ip

	s.queuedSig = make(chan struct {
		sig Signature
		rec AggregationOutputReceiver
		ctx context.Context
	}, s.config.SigQueueSize)

	s.queuedPart = make(chan struct {
		pd  Descriptor
		ctx context.Context
	})

	s.runningProtos = make(map[ID]struct {
		pd           Descriptor
		incoming     chan Share
		disconnected chan sessions.NodeID
	})

	s.connectedNodes = make(map[sessions.NodeID]utils.Set[ID])
	s.connectedNodesCond = *sync.NewCond(&s.connectedNodesMu)

	s.completedProtos = make([]Descriptor, 0)

	return s, nil
}

func (s *Executor) Run(ctx context.Context, trans Transport) error { // TODO: cancel if ctx is cancelled

	s.transport = trans

	doneWithShareTransport := make(chan struct{})

	shareRoutines := errgroup.Group{}

	// processes incoming shares from the transport
	shareRoutines.Go(func() error {
		for {
			select {
			case incShare, more := <-s.transport.IncomingShares():

				if !more {
					s.Logf("transport closed incoming share channel")
					return nil
				}

				s.runningProtoMu.RLock()
				proto, protoExists := s.runningProtos[incShare.ProtocolID]
				s.runningProtoMu.RUnlock()
				if !protoExists {
					err := fmt.Errorf("invalide incoming share from sender %s: protocol %s is not running", incShare.From, incShare.ProtocolID)
					s.Logf("error recieving share: %s", err)
					continue
				}
				proto.incoming <- incShare
			case <-doneWithShareTransport:
				s.Logf("is done with share transport")
				return nil
			}
		}
	})

	protoRoutines, prctx := errgroup.WithContext(ctx)
	// processes the protocol signature queue as coordinator and aggregator
	for i := 0; i < s.config.MaxAggregation; i++ {
		protoRoutines.Go(
			func() error {
				for {
					select {
					case qsig, more := <-s.queuedSig:
						if !more {
							//s.Logf("closed signature queue")
							return nil
						}
						s.Logf("picked up signature from queue: %s", qsig.sig)
						err := s.runSignature(qsig.ctx, qsig.sig, qsig.rec)
						if err != nil {
							s.Logf("error: %s", err)
							return fmt.Errorf("error in signature queue processing: %w", err)
						}
					case <-prctx.Done():
						s.Logf("context was cancelled, error: %s", prctx.Err())
						return nil
					}

				}
			})
	}

	// processes the protocol descriptor queue as participant
	for i := 0; i < s.config.MaxParticipation; i++ {
		protoRoutines.Go(func() error {
			for {
				select {
				case qpd, more := <-s.queuedPart:
					if !more {
						s.Logf("closed participation queue")
						return nil
					}
					if err := s.runAsParticipant(qpd.ctx, qpd.pd); err != nil {
						s.Logf("error: %s", err)
						return fmt.Errorf("error during protocol execution as participant: %w", err)
					}
				case <-prctx.Done():
					s.Logf("context was cancelled, error: %s", prctx.Err())
					return nil
				}

			}
		})
	}

	go func() {
		// processes incoming coordinator events
		for ev := range s.upstream.Incoming {

			if ev.EventType != Started {
				continue
			}

			if !s.isParticipantFor(ev.Descriptor) {
				continue
			}

			if s.isKeySwitchReceiver(ev.Descriptor) {
				continue
			}

			s.queuedPart <- struct {
				pd  Descriptor
				ctx context.Context
			}{pd: ev.Descriptor, ctx: ctx}
		}

		s.Logf("upstream coordinator closed, closing queues")
		close(s.queuedSig)
		close(s.queuedPart)
	}()

	err := protoRoutines.Wait()
	if err != nil {
		return err
	}
	s.Logf("all protocol processing routine terminated, closing upstream coordinator outgoing channel")

	//s.runningProtoWg.Wait()
	close(doneWithShareTransport)
	shareRoutines.Wait()

	close(s.upstream.Outgoing)
	s.Logf("all running protocol done, Run return")
	return nil
}

func (s *Executor) runAsAggregator(ctx context.Context, sess *sessions.Session, pd Descriptor) (aggOut AggregationOutput) {

	if !s.isAggregatorFor(pd) {
		panic(fmt.Errorf("not the aggregator for protocol"))
	}

	proto, err := NewProtocol(pd, sess)
	if err != nil {
		panic(err)
	}
	pid := pd.ID()

	// registers the protocol
	var aggregation <-chan AggregationOutput
	var disconnected chan sessions.NodeID
	s.runningProtoMu.Lock()
	s.connectedNodesMu.RLock()
	incoming := make(chan Share)
	disconnected = make(chan sessions.NodeID, len(pd.Participants))
	s.runningProtos[pid] = struct {
		pd           Descriptor
		incoming     chan Share
		disconnected chan sessions.NodeID
	}{
		pd:           pd,
		incoming:     incoming,
		disconnected: disconnected,
	}

	// nodes might have disconnected before the protocol started
	for _, nid := range pd.Participants {
		if _, has := s.connectedNodes[nid]; !has {
			disconnected <- nid
		}
	}
	s.connectedNodesMu.RUnlock()
	s.runningProtoMu.Unlock()

	clearProtocol := func() {
		s.connectedNodesMu.Lock()
		for _, part := range pd.Participants {
			s.connectedNodes[part].Remove(pd.ID())
		}
		s.connectedNodesMu.Unlock()
		s.connectedNodesCond.Broadcast()

		s.runningProtoMu.Lock()
		delete(s.runningProtos, pid)
		s.runningProtoMu.Unlock()
	}
	//s.runningProtoWg.Add(1)

	// runs the aggregation
	aggCtx, cancelAgg := context.WithCancel(ctx)
	aggregation = proto.Aggregate(aggCtx, incoming)

	s.Logf("started protocol %s", pd)

	input, err := s.inputProvider(ctx, pd)
	if err != nil {
		cancelAgg()
		clearProtocol()
		aggOut.Error = fmt.Errorf("cannot get input for protocol: %w", err)
		return
	}

	s.upstream.Outgoing <- Event{EventType: Started, Descriptor: pd}

	if s.isParticipantFor(pd) {

		sk, err := sess.GetSecretKeyForGroup(pd.Participants) // TODO: cache
		if err != nil {
			panic(err)
		}

		// runs the share generation and sending to aggregator
		share := proto.AllocateShare()
		err = proto.GenShare(sk, input, &share)
		if err != nil {
			panic(err)
		}
		s.transport.OutgoingShares() <- share
		s.Logf("completed participation for %s", pd.HID())
	}

	//go func() {
	aggOut.Descriptor = pd
	for done := false; !done; {
		select {
		case aggOut = <-aggregation:
			done = true
		case participantID := <-disconnected:

			if proto.HasShareFrom(participantID) {
				s.Logf("node %s disconnected after providing its share, protocol %s", participantID, pd.HID())
				continue
			}

			s.Logf("node %s disconnected before providing its share, aborting protocol %s", participantID, pd.HID())
			done = true
			aggOut.Error = fmt.Errorf("node %s disconnected before providing its share", participantID)
		}
	}
	cancelAgg()
	clearProtocol()

	if aggOut.Error != nil {
		s.upstream.Outgoing <- Event{EventType: Failed, Descriptor: pd}
		return
	} else {
		s.upstream.Outgoing <- Event{EventType: Completed, Descriptor: pd}
	}

	s.runningProtoMu.Lock()
	s.completedProtos = append(s.completedProtos, pd)
	s.runningProtoMu.Unlock()

	s.Logf("completed aggregation for %s", pd.HID())
	//}()
	return
}

func (s *Executor) RunSignature(ctx context.Context, sig Signature, aggOutRec AggregationOutputReceiver) (err error) {
	s.queuedSig <- struct {
		sig Signature
		rec AggregationOutputReceiver
		ctx context.Context
	}{
		sig: sig,
		rec: aggOutRec,
		ctx: ctx,
	}
	return nil
}

func (s *Executor) runSignature(ctx context.Context, sig Signature, aggOutRec AggregationOutputReceiver) (err error) {
	sess, has := s.sessProvider.GetSessionFromContext(ctx)
	if !has {
		return fmt.Errorf("could not extract session from context")
	}

	//s.Logf("getting key operation descriptor: %s", sig)
	var aggOut AggregationOutput
	for {
		// gets a protocol descriptor with available nodes
		pd := s.getProtocolDescriptor(sig, sess)

		// attempts to run the protocol
		if aggOut = s.runAsAggregator(ctx, sess, pd); aggOut.Error == nil {
			break
		}

		s.Logf("[%s] error during aggregation: %s, retrying...", pd.HID(), aggOut.Error)
	}

	//s.Logf("running key operation descriptor: %s", pd)

	err = aggOutRec(ctx, aggOut)
	if err != nil {
		return fmt.Errorf("error calling aggregation output receiver: %w", err)
	}

	return
}

func (s *Executor) RunDescriptorAsAggregator(ctx context.Context, pd Descriptor) (aggOut *AggregationOutput, err error) {

	sess, has := s.sessProvider.GetSessionFromContext(ctx)
	if !has {
		return nil, fmt.Errorf("could not extract session from context")
	}

	agg := s.runAsAggregator(ctx, sess, pd)
	return &agg, agg.Error
}

func (s *Executor) runAsParticipant(ctx context.Context, pd Descriptor) error {

	if !s.isParticipantFor(pd) {
		return fmt.Errorf("not a participant for protocol")
	}

	sess, has := s.sessProvider.GetSessionFromContext(ctx)
	if !has {
		return fmt.Errorf("could not extract session from context")
	}

	s.Logf("started protocol %s as participant", pd.HID())

	proto, err := NewProtocol(pd, sess)
	if err != nil {
		return err
	}

	// runs the share generation and sending to aggregator
	share := proto.AllocateShare()

	sk, err := sess.GetSecretKeyForGroup(pd.Participants) // TODO cache ?
	if err != nil {
		return err
	}

	input, err := s.inputProvider(ctx, pd)
	if err != nil {
		return fmt.Errorf("cannot get input for protocol: %w", err)
	}

	err = proto.GenShare(sk, input, &share)
	if err != nil {
		return err
	}

	s.Logf("sending share for %s", pd.HID())
	s.transport.OutgoingShares() <- share
	s.Logf("completed participation for %s", pd.HID())
	return nil
}

func (s *Executor) GetOutput(ctx context.Context, aggOut AggregationOutput, rec interface{}) error {
	sess, has := s.sessProvider.GetSessionFromContext(ctx)
	if !has {
		return fmt.Errorf("no session found in context")
	}

	input, err := s.inputProvider(ctx, aggOut.Descriptor)
	if err != nil {
		return fmt.Errorf("cannot get input for protocol: %w", err)
	}

	p, err := NewProtocol(aggOut.Descriptor, sess)
	if err != nil {
		return fmt.Errorf("cannot create protocol for output: %w", err)
	}

	return p.Output(input, aggOut, rec)
}

// Register is called by the transport when a new peer register itself for the setup.
func (s *Executor) Register(peer sessions.NodeID) error {
	s.connectedNodesMu.Lock()

	if _, has := s.connectedNodes[peer]; has {
		panic("attempting to register a registered node")
	}

	s.connectedNodes[peer] = make(utils.Set[ID])
	s.connectedNodesMu.Unlock()
	s.connectedNodesCond.Broadcast()

	s.Logf("registered peer %v, %d online nodes", peer, len(s.connectedNodes))
	return nil // TODO: Implement
}

// Unregister is called by the transport when a peer is unregistered from the setup.
func (s *Executor) Unregister(peer sessions.NodeID) error {

	s.connectedNodesMu.Lock()
	_, has := s.connectedNodes[peer]
	if !has {
		panic("unregistering an unregistered node")
	}

	s.DisconnectedNode(peer)

	delete(s.connectedNodes, peer)
	s.connectedNodesMu.Unlock()

	s.Logf("unregistered peer %v, %d online nodes", peer, len(s.connectedNodes))
	return nil // TODO: Implement
}

func (s *Executor) getAvailable() utils.Set[sessions.NodeID] {
	available := make(utils.Set[sessions.NodeID])
	for nid, nProtos := range s.connectedNodes {
		if len(nProtos) < s.config.MaxProtoPerNode {
			available.Add(nid)
		}
	}
	return available
}

func (s *Executor) getProtocolDescriptor(sig Signature, sess *sessions.Session) Descriptor {
	pd := Descriptor{Signature: sig, Aggregator: s.self}

	var available, selected utils.Set[sessions.NodeID]
	switch sig.Type {
	case DEC:
		if sess.Contains(sessions.NodeID(sig.Args["target"])) {
			selected = utils.NewSingletonSet(sessions.NodeID(sig.Args["target"]))
			break
		}
		fallthrough
	default:
		selected = utils.NewEmptySet[sessions.NodeID]()
	}

	s.connectedNodesMu.Lock()
	for {
		available = s.getAvailable()
		available.Remove(selected.Elements()...)
		if len(selected)+len(available) >= sess.Threshold {
			break
		}
		s.connectedNodesCond.Wait()
	}

	selected.AddAll(utils.GetRandomSetOfSize(sess.Threshold-len(selected), available))
	pd.Participants = selected.Elements()
	slices.Sort(pd.Participants)
	for nid := range selected {
		nodeProto := s.connectedNodes[nid]
		nodeProto.Add(pd.ID())
	}

	s.connectedNodesMu.Unlock()

	return pd
}

func (s *Executor) DisconnectedNode(id sessions.NodeID) {
	s.runningProtoMu.RLock()
	protoIds := s.connectedNodes[id]
	for pid := range protoIds {
		s.runningProtos[pid].disconnected <- id
	}
	s.runningProtoMu.RUnlock()
}

func (s *Executor) Logf(msg string, v ...any) {
	log.Printf("%s | [executor] %s\n", s.self, fmt.Sprintf(msg, v...))
}

func (s *Executor) NodeID() sessions.NodeID {
	return s.self
}

func (s *Executor) isAggregatorFor(pd Descriptor) bool {
	return pd.Aggregator == s.self
}

func (s *Executor) isParticipantFor(pd Descriptor) bool {
	for _, part := range pd.Participants {
		if part == s.self {
			return true
		}
	}
	return false
}

func (s *Executor) isKeySwitchReceiver(pd Descriptor) bool {
	if pd.Signature.Type == DEC || pd.Signature.Type == PCKS {
		target := pd.Signature.Args["target"]
		return s.self == sessions.NodeID(target)
	}
	return false
}

type TestTransport struct {
	incoming, outgoing chan Share
}

func NewTestTransport() *TestTransport {
	return &TestTransport{incoming: make(chan Share), outgoing: nil}
}

func (tt *TestTransport) TransportFor(nid sessions.NodeID) *TestTransport {
	tnt := new(TestTransport)
	tnt.outgoing = tt.incoming
	return tnt
}

func (tt *TestTransport) IncomingShares() <-chan Share {
	return tt.incoming
}

func (tt *TestTransport) OutgoingShares() chan<- Share {
	return tt.outgoing
}
