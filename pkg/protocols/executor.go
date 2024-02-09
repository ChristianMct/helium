package protocols

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/ldsec/helium/pkg/objectstore"
	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/utils"
)

const parallelAggregation int = 10
const parallelParticipation int = 10

type Transport interface {
	// GetAggregationFrom queries the designated node id (typically, the aggregator) for the
	// aggregated share of the designated protocol.
	GetAggregation(context.Context, Descriptor) (*AggregationOutput, error)

	OutgoingShares() chan<- Share
	IncomingShares() <-chan Share
}

type Coordinator interface {
	Incoming() <-chan Event
	Outgoing() chan<- Event
}

type EventType int32

const (
	Completed EventType = iota
	Started
	Executing
	Failed
)

type Event struct {
	EventType
	Descriptor
}

type Executor struct {
	self pkg.NodeID

	sessions    pkg.SessionProvider
	transport   Transport
	coordinator Coordinator

	L             sync.RWMutex
	runningProtos map[pkg.ProtocolID]struct {
		pd           Descriptor
		incoming     chan Share
		disconnected chan pkg.NodeID
	}

	nodesToProtocols map[pkg.NodeID]utils.Set[pkg.ProtocolID]

	completedProtos []Descriptor

	ResultBackend
	rkgRound1Results map[pkg.ProtocolID]Share // TODO remove
}

func NewExectutor(ownId pkg.NodeID, sessions pkg.SessionProvider, trans Transport, coord Coordinator, objStore objectstore.ObjectStore) (*Executor, error) {
	s := new(Executor)
	s.self = ownId
	s.sessions = sessions

	s.coordinator = coord
	s.transport = trans

	s.runningProtos = make(map[pkg.ProtocolID]struct {
		pd           Descriptor
		incoming     chan Share
		disconnected chan pkg.NodeID
	})

	s.completedProtos = make([]Descriptor, 0)

	s.ResultBackend = newObjStoreResultBackend(objStore)
	s.rkgRound1Results = make(map[pkg.ProtocolID]Share)

	s.nodesToProtocols = make(map[pkg.NodeID]utils.Set[pkg.ProtocolID])
	return s, nil
}

func (s *Executor) RunService(ctx context.Context) {
	// get incoming shares and put them into proto.incoming.
	go func() {
		inc := s.transport.IncomingShares()
		for incShare := range inc {
			s.L.RLock()
			proto, protoExists := s.runningProtos[incShare.ProtocolID]
			s.L.RUnlock()
			if !protoExists {
				s.Logf("dropped share from sender %s: protocol %s is not running", incShare.From, incShare.ProtocolID)
				continue
			}
			// sends received share to the incoming channel of the destination protocol.
			proto.incoming <- incShare
			//s.Logf("received share from sender %s for protocol %s", incShare.From, incShare.ProtocolID)
		}
	}()
}

func (s *Executor) RunProtocol(ctx context.Context, pd Descriptor) {

	sess, has := s.sessions.GetSessionFromContext(ctx)
	if !has {
		panic(fmt.Errorf("session could not extract session from context"))
	}

	if !s.hasRoleIn(pd) {
		s.Logf("not running %s, no role in the protocol", pd.HID())
		return
	}

	s.Logf("started running %s", pd.HID())

	// creating the protocol resources

	var input Input
	if pd.Signature.Type == RKG_2 {
		rkgRound1Pd := Descriptor{Signature: Signature{Type: RKG_1, Args: pd.Signature.Args}, Participants: pd.Participants, Aggregator: pd.Aggregator}
		r1Out, err := s.GetProtocolOutput(ctx, rkgRound1Pd)
		if err != nil {
			panic(fmt.Errorf("could not retrieve round 1 output: %s", err))
		}
		input = r1Out.Share.MHEShare
	}
	proto, err := NewProtocol(pd, sess, input)
	if err != nil {
		panic(err)
	}
	pid := pd.ID()

	var aggregation chan AggregationOutput
	var disconnected chan pkg.NodeID
	if s.isAggregatorFor(pd) {
		// registers the protocol
		s.L.Lock()
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
		s.L.Unlock()
		// runs the aggregation
		aggregation, err = proto.Aggregate(ctx, incoming)
		if err != nil {
			panic(err)
		}
		s.coordinator.Outgoing() <- Event{EventType: Started, Descriptor: pd}
	}

	if s.isParticipantFor(pd) {
		// runs the share generation and sending to aggregator
		share := proto.AllocateShare()
		proto.GenShare(&share)
		s.transport.OutgoingShares() <- share
	}

	if s.isAggregatorFor(pd) {
		// waits for the result or failures
		var aggOut AggregationOutput
		var errAgg error
		abort := make(chan pkg.NodeID)
		for done := false; !done; {
			select {
			case aggOut = <-aggregation:
				if aggOut.Error != nil {
					panic(aggOut.Error)
				}
				done = true
			case participantId := <-disconnected:

				if proto.HasShareFrom(participantId) {
					s.Logf("node %s disconnected after providing its share, protocol %s continuing...", participantId, pd.HID())
					continue
				}

				time.AfterFunc(time.Second, func() { // leaves some time to process some more messages
					participantId := participantId
					abort <- participantId
				})
				//errAgg = fmt.Errorf("participant disconnected before providing its share: %s", participantId)
			case nid := <-abort:
				done = true
				errAgg = fmt.Errorf("aborted due to disconnection of %s before providing its share", nid)
			}
		}

		if errAgg != nil {
			s.coordinator.Outgoing() <- Event{EventType: Failed, Descriptor: pd}
		} else {
			if pd.Signature.Type == RKG_1 {
				s.rkgRound1Results[pd.ID()] = aggOut.Share // TODO revamp result backend to store all round results
			} else {
				err = s.ResultBackend.Put(pd, aggOut.Share)
				if err != nil {
					panic(err)
				}
			}
			s.coordinator.Outgoing() <- Event{EventType: Completed, Descriptor: pd}
		}

		//s.Logf("[Aggregate] Finished aggregating for pd: %v", pd)
		s.L.Lock()
		delete(s.runningProtos, pid)
		s.completedProtos = append(s.completedProtos, pd)
		s.L.Unlock()

		s.Logf("completed aggregation for %s", pd.HID())
	}

	s.Logf("completed execution for %s", pd.HID())
}

func (s *Executor) GetProtocolOutput(ctx context.Context, pd Descriptor) (out *AggregationOutput, err error) {

	// first checks if it has the share locally
	share := Share{}
	if pd.Signature.Type == RKG_1 {
		var has bool
		share, has = s.rkgRound1Results[pd.ID()]
		if !has {
			err = fmt.Errorf("no rkg share for round 1")
		}
	} else {
		lattigoShare := pd.Signature.Type.Share()
		err = s.ResultBackend.GetShare(pd.Signature, lattigoShare)
		share.MHEShare = lattigoShare
	}

	// otherwise, query the aggregator
	if err != nil {
		if pd.Aggregator == s.self {
			return nil, fmt.Errorf("node is aggregator but has error on backend: %s", err)
		}

		if out, err = s.transport.GetAggregation(ctx, pd); err != nil {
			return nil, err
		}
		s.Logf("queried aggregation for %s", pd.HID())

		share = out.Share
		s.ResultBackend.Put(pd, out.Share)
		if pd.Signature.Type == RKG_1 {
			s.rkgRound1Results[pd.ID()] = out.Share
		}
	}

	return &AggregationOutput{Share: share}, nil
}

func (s *Executor) DisconnectedNode(id pkg.NodeID) {
	s.L.RLock()
	protoIds, _ := s.nodesToProtocols[id]
	for pid := range protoIds {
		s.runningProtos[pid].disconnected <- id
	}
	s.L.RUnlock()
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

type localTransport struct {
	incoming <-chan Share
	outgoing chan<- Share
}

func (pe *localTransport) OutgoingShares() chan<- Share {
	return pe.outgoing
}

func (pe *localTransport) IncomingShares() <-chan Share {
	return pe.incoming
}
