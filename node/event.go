package node

import (
	"fmt"

	"github.com/ChristianMct/helium/circuits"
	"github.com/ChristianMct/helium/protocols"
)

// Event is an entry of a node's coordination log: either a protocol event
// (published by the coordinator and the protocol runner) or a circuit event
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
