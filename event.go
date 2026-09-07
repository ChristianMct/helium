package helium

import (
	"fmt"

	"github.com/ChristianMct/helium/api"
	"github.com/ChristianMct/helium/api/pb"
	"github.com/ChristianMct/helium/circuits"
	"github.com/ChristianMct/helium/protocols"
)

// Event is an event of the node-level coordination log: either a protocol event
// (published by the coordinator and the protocol engine) or a circuit event
// (published by the circuit evaluator). Exactly one of the fields is set.
type Event struct {
	Protocol *protocols.Event
	Circuit  *circuits.Event
}

// String returns a string representation of the event.
func (ev Event) String() string {
	switch {
	case ev.Protocol != nil:
		return fmt.Sprintf("PROTOCOL %s", ev.Protocol)
	case ev.Circuit != nil:
		return fmt.Sprintf("CIRCUIT %s", ev.Circuit)
	}
	return "INVALID EVENT"
}

func getNodeEvent(ev Event) (*pb.NodeEvent, error) {
	switch {
	case ev.Protocol != nil:
		return &pb.NodeEvent{Event: &pb.NodeEvent_ProtocolEvent{ProtocolEvent: api.GetProtocolEvent(*ev.Protocol)}}, nil
	case ev.Circuit != nil:
		return &pb.NodeEvent{Event: &pb.NodeEvent_CircuitEvent{CircuitEvent: api.GetCircuitEvent(*ev.Circuit)}}, nil
	}
	return nil, fmt.Errorf("invalid event: neither a protocol nor a circuit event")
}

func toNodeEvent(apiEvent *pb.NodeEvent) (Event, error) {
	switch e := apiEvent.Event.(type) {
	case *pb.NodeEvent_ProtocolEvent:
		ev := api.ToProtocolEvent(e.ProtocolEvent)
		return Event{Protocol: &ev}, nil
	case *pb.NodeEvent_CircuitEvent:
		ev := api.ToCircuitEvent(e.CircuitEvent)
		return Event{Circuit: &ev}, nil
	}
	return Event{}, fmt.Errorf("invalid event: neither a protocol nor a circuit event")
}
