package protocols

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/utils"
)

const numProtoPerNode = 5

type Transport interface {
	OutgoingShares() chan<- Share
	IncomingShares() <-chan Share
}

type Coordinator interface {
	Incoming() <-chan Event
	Outgoing() chan<- Event
}

type InputProvider func(ctx context.Context, pd Descriptor) (Input, error)

type AggregationOutputBackend interface {
	Put(context.Context, AggregationOutput) error
	Get(context.Context, Descriptor) (*AggregationOutput, error)
}

type EventType int32

const (
	Completed EventType = iota
	Started
	Executing
	Failed
)

var evtypeToString = []string{"COMPLETED", "STARTED", "EXECUTING", "FAILED"}

func (t EventType) String() string {
	if int(t) > len(evtypeToString) {
		t = 0
	}
	return evtypeToString[t]
}

type Event struct {
	EventType
	Descriptor
}

func (ev Event) String() string {
	return fmt.Sprintf("%s: %s", ev.EventType, ev.Signature)
}

type Executor struct {
	self pkg.NodeID

	sessions      pkg.SessionProvider
	transport     Transport
	coordinator   Coordinator
	inputProvider InputProvider
	aggOutBackend AggregationOutputBackend

	// node tracking
	connectedNodes     map[pkg.NodeID]utils.Set[pkg.ProtocolID]
	connectedNodesMu   sync.RWMutex
	connectedNodesCond sync.Cond

	// protocol tracking
	runningProtoMu sync.RWMutex
	runningProtos  map[pkg.ProtocolID]struct {
		pd           Descriptor
		incoming     chan Share
		disconnected chan pkg.NodeID
	}
	runningProtoWg sync.WaitGroup

	nodesToProtocols map[pkg.NodeID]utils.Set[pkg.ProtocolID]

	completedProtos []Descriptor

	// ResultBackend
	// rkgRound1Results map[pkg.ProtocolID]Share // TODO remove
}

func NewExectutor(ownId pkg.NodeID, sessions pkg.SessionProvider, coord Coordinator, ip InputProvider, agbk AggregationOutputBackend, trans Transport) (*Executor, error) {
	s := new(Executor)
	s.self = ownId
	s.sessions = sessions

	s.coordinator = coord
	s.transport = trans
	s.inputProvider = ip
	s.aggOutBackend = agbk

	s.runningProtos = make(map[pkg.ProtocolID]struct {
		pd           Descriptor
		incoming     chan Share
		disconnected chan pkg.NodeID
	})

	s.connectedNodes = make(map[pkg.NodeID]utils.Set[pkg.ProtocolID])
	s.connectedNodesCond = *sync.NewCond(&s.connectedNodesMu)

	s.completedProtos = make([]Descriptor, 0)

	// s.ResultBackend = newObjStoreResultBackend(objStore)
	// s.rkgRound1Results = make(map[pkg.ProtocolID]Share)

	s.nodesToProtocols = make(map[pkg.NodeID]utils.Set[pkg.ProtocolID])
	return s, nil
}

func (s *Executor) Run(ctx context.Context) {

	// processes incoming shares from the transport
	go func() {
		inc := s.transport.IncomingShares()
		for incShare := range inc {
			s.runningProtoMu.RLock()
			proto, protoExists := s.runningProtos[incShare.ProtocolID]
			s.runningProtoMu.RUnlock()
			if !protoExists {
				s.Logf("dropped share from sender %s: protocol %s is not running", incShare.From, incShare.ProtocolID)
				continue
			}
			// sends received share to the incoming channel of the destination protocol.
			proto.incoming <- incShare
			//s.Logf("received share from sender %s for protocol %s", incShare.From, incShare.ProtocolID)
		}
	}()

	// processes incoming coordinator events
	for ev := range s.coordinator.Incoming() {

		if ev.EventType != Started {
			continue
		}

		if !s.isParticipantFor(ev.Descriptor) {
			continue
		}

		if s.isKeySwitchReceiver(ev.Descriptor) {
			continue
		}

		err := s.RunProtocolAsParticipant(ctx, ev.Descriptor)
		if err != nil {
			panic(fmt.Errorf("error during protocol execution as participant: %w", err))
		}

	}

	s.runningProtoWg.Wait()

	close(s.coordinator.Outgoing())

	return

}

func (s *Executor) runAsAggregator(ctx context.Context, sess *pkg.Session, pd Descriptor) (aggOut chan AggregationOutput, err error) {

	input, err := s.inputProvider(ctx, pd)
	if err != nil {
		return nil, err
	}

	proto, err := NewProtocol(pd, sess, input)
	if err != nil {
		panic(err)
	}
	pid := pd.ID()

	// registers the protocol
	var aggregation chan AggregationOutput
	var disconnected chan pkg.NodeID
	s.runningProtoMu.Lock()
	incoming := make(chan Share)
	disconnected = make(chan pkg.NodeID, len(pd.Participants))
	s.runningProtos[pid] = struct {
		pd           Descriptor
		incoming     chan Share
		disconnected chan pkg.NodeID
	}{
		pd:           pd,
		incoming:     incoming,
		disconnected: disconnected,
	}
	s.runningProtoMu.Unlock()
	s.runningProtoWg.Add(1)

	// runs the aggregation
	aggregation, err = proto.Aggregate(ctx, incoming)
	if err != nil {
		panic(err)
	}

	s.Logf("started protocol %s with input %T", pd, input)

	s.coordinator.Outgoing() <- Event{EventType: Started, Descriptor: pd}

	if s.isParticipantFor(pd) {
		// runs the share generation and sending to aggregator
		share := proto.AllocateShare()
		proto.GenShare(&share)
		s.transport.OutgoingShares() <- share
		s.Logf("completed participation for %s", pd.HID())
	}

	aggOut = make(chan AggregationOutput, 1)
	go func() {
		var agg AggregationOutput
		agg.Descriptor = pd
		abort := make(chan pkg.NodeID)
		for done := false; !done; {
			select {
			case agg = <-aggregation:
				done = true
			case participantId := <-disconnected:

				if proto.HasShareFrom(participantId) {
					s.Logf("node %s disconnected after providing its share, protocol %s", participantId, pd.HID())
					continue
				}

				s.Logf("node %s disconnected before providing its share, protocol %s", participantId, pd.HID())

				// time.AfterFunc(time.Second, func() { // leaves some time to process some more messages
				// 	participantId := participantId
				// 	abort <- participantId
				// })
			case <-abort:
				done = true
				agg.Error = fmt.Errorf("protocol aggregation has aborted aborted")
			}
		}

		aggOut <- agg

		if agg.Error != nil {
			s.coordinator.Outgoing() <- Event{EventType: Failed, Descriptor: pd}
		} else {
			s.coordinator.Outgoing() <- Event{EventType: Completed, Descriptor: pd}
		}

		s.connectedNodesMu.Lock()
		for _, part := range pd.Participants {
			s.connectedNodes[part].Remove(pd.ID())
		}
		s.connectedNodesMu.Unlock()
		s.connectedNodesCond.Broadcast()

		s.runningProtoMu.Lock()
		delete(s.runningProtos, pid)
		s.runningProtoMu.Unlock()
		s.runningProtoWg.Done()

		err := s.aggOutBackend.Put(ctx, agg)
		if err != nil {
			panic(err)
		}
		s.runningProtoMu.Lock()
		s.completedProtos = append(s.completedProtos, pd)
		s.runningProtoMu.Unlock()

		s.Logf("completed aggregation for %s", pd.HID())
	}()
	return
}

func (s *Executor) RunSignatureAsAggregator(ctx context.Context, sig Signature) (aggOut chan AggregationOutput, err error) {

	sess, has := s.sessions.GetSessionFromContext(ctx)
	if !has {
		return nil, fmt.Errorf("session could not extract session from context")
	}

	//s.Logf("getting key operation descriptor: %s", sig)

	pd := s.getProtocolDescriptor(sig, sess)

	//s.Logf("running key operation descriptor: %s", pd)

	return s.runAsAggregator(ctx, sess, pd)
}

func (s *Executor) RunDescriptorAsAggregator(ctx context.Context, pd Descriptor) (aggOut chan AggregationOutput, err error) {

	sess, has := s.sessions.GetSessionFromContext(ctx)
	if !has {
		return nil, fmt.Errorf("session could not extract session from context")
	}

	return s.runAsAggregator(ctx, sess, pd)
}

func (s *Executor) RunProtocolAsParticipant(ctx context.Context, pd Descriptor) error {

	sess, has := s.sessions.GetSessionFromContext(ctx)
	if !has {
		return fmt.Errorf("session could not extract session from context")
	}

	input, err := s.inputProvider(ctx, pd)
	if err != nil {
		return fmt.Errorf("error while retreiving input: %w", err)
	}

	proto, err := NewProtocol(pd, sess, input)
	if err != nil {
		panic(err)
	}

	// runs the share generation and sending to aggregator
	share := proto.AllocateShare()
	err = proto.GenShare(&share)
	if err != nil {
		return err
	}
	s.transport.OutgoingShares() <- share
	s.Logf("completed participation for %s", pd.HID())
	return nil
}

func (s *Executor) GetOutput(ctx context.Context, aggOut AggregationOutput) (out Output) {
	sess, has := s.sessions.GetSessionFromContext(ctx)
	if !has {
		out.Error = fmt.Errorf("no session found in context")
		return
	}

	input, err := s.inputProvider(ctx, aggOut.Descriptor)
	if err != nil {
		out.Error = err
	}

	p, err := NewProtocol(aggOut.Descriptor, sess, input)
	if err != nil {
		out.Error = fmt.Errorf("cannot create protocol: %s", err)
		return
	}
	return <-p.Output(aggOut)
}

// Register is called by the transport when a new peer register itself for the setup.
func (s *Executor) Register(peer pkg.NodeID) error {
	s.connectedNodesMu.Lock()
	defer s.connectedNodesCond.Broadcast()
	defer s.connectedNodesMu.Unlock()

	if _, has := s.connectedNodes[peer]; has {
		panic("attempting to register a registered node")
	}

	s.connectedNodes[peer] = make(utils.Set[pkg.ProtocolID])

	s.Logf("[Node] registered peer %v, %d online nodes", peer, len(s.connectedNodes))
	return nil // TODO: Implement
}

// Unregister is called by the transport when a peer is unregistered from the setup.
func (s *Executor) Unregister(peer pkg.NodeID) error {

	s.connectedNodesMu.Lock()
	_, has := s.connectedNodes[peer]
	if !has {
		panic("unregistering an unregistered node")
	}

	s.DisconnectedNode(peer)

	delete(s.connectedNodes, peer)
	s.connectedNodesMu.Unlock()

	s.Logf("[Node] unregistered peer %v, %d online nodes", peer, len(s.connectedNodes))
	return nil // TODO: Implement
}

func (s *Executor) getAvailable() utils.Set[pkg.NodeID] {
	available := make(utils.Set[pkg.NodeID])
	for nid, nProtos := range s.connectedNodes {
		if len(nProtos) < numProtoPerNode {
			available.Add(nid)
		}
	}
	return available
}

func (s *Executor) getProtocolDescriptor(sig Signature, sess *pkg.Session) Descriptor {
	pd := Descriptor{Signature: sig, Aggregator: s.self}

	var available, selected utils.Set[pkg.NodeID]
	switch sig.Type {
	case DEC:
		if sess.Contains(pkg.NodeID(sig.Args["target"])) {
			selected = utils.NewSingletonSet(pkg.NodeID(sig.Args["target"]))
			break
		}
		fallthrough
	default:
		selected = utils.NewEmptySet[pkg.NodeID]()
	}

	s.connectedNodesMu.Lock()
	for {
		available = s.getAvailable()
		available.Remove(selected.Elements()...)
		if len(selected)+len(available) >= sess.T {
			break
		}
		s.connectedNodesCond.Wait()
	}

	selected.AddAll(utils.GetRandomSetOfSize(sess.T-len(selected), available))
	pd.Participants = selected.Elements()
	for nid := range selected {
		nodeProto := s.connectedNodes[nid]
		nodeProto.Add(pd.ID())
	}
	s.connectedNodesMu.Unlock()

	return pd
}

func (s *Executor) DisconnectedNode(id pkg.NodeID) {
	s.runningProtoMu.RLock()
	protoIds, _ := s.nodesToProtocols[id]
	for pid := range protoIds {
		s.runningProtos[pid].disconnected <- id
	}
	s.runningProtoMu.RUnlock()
}

func (s *Executor) Logf(msg string, v ...any) {
	log.Printf("%s | %s\n", s.self, fmt.Sprintf(msg, v...))
}

func (s *Executor) NodeID() pkg.NodeID {
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

func (s *Executor) hasRoleIn(pd Descriptor) bool {
	return s.isAggregatorFor(pd) || s.isParticipantFor(pd)
}

func (s *Executor) isKeySwitchReceiver(pd Descriptor) bool {
	if pd.Signature.Type == DEC || pd.Signature.Type == PCKS {
		target := pd.Signature.Args["target"]
		return s.self == pkg.NodeID(target)
	}
	return false
}

type testCoordinator struct {
	incoming, outgoing chan Event
	clients            map[pkg.NodeID]*testCoordinator
}

func NewTestCoordinator() *testCoordinator {
	tc := &testCoordinator{incoming: make(chan Event), outgoing: make(chan Event), clients: make(map[pkg.NodeID]*testCoordinator)}
	go func() {
		for ev := range tc.outgoing {
			for _, cli := range tc.clients {
				cli.incoming <- ev
			}
		}
		for _, cli := range tc.clients {
			close(cli.incoming)
		}
	}()
	return tc
}

func (tc *testCoordinator) Close() {
	close(tc.outgoing)
	close(tc.incoming)
}

func (tc *testCoordinator) NewNodeCoordinator(nid pkg.NodeID) *testCoordinator {
	tcc := &testCoordinator{incoming: make(chan Event), outgoing: make(chan Event)}
	tc.clients[nid] = tcc
	return tcc
}

func (tc *testCoordinator) Incoming() <-chan Event {
	return tc.incoming
}

func (tc *testCoordinator) Outgoing() chan<- Event {
	return tc.outgoing
}

type testTransport struct {
	incoming, outgoing chan Share
}

func NewTestTransport() *testTransport {
	return &testTransport{incoming: make(chan Share), outgoing: make(chan Share)}
}

func (tt *testTransport) TransportFor(nid pkg.NodeID) *testTransport {
	tnt := new(testTransport)
	tnt.incoming = make(chan Share)
	tnt.outgoing = make(chan Share)

	go func() {
		close(tnt.incoming)
		for share := range tnt.outgoing {
			tt.incoming <- share
			//log.Printf("trans | share from %s for %s sent to aggregator\n", nid, share.ProtocolID[:25])
		}
	}()

	return tnt
}

func (tt *testTransport) IncomingShares() <-chan Share {
	return tt.incoming
}

func (tt *testTransport) OutgoingShares() chan<- Share {
	return tt.outgoing
}
