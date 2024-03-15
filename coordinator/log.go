// Package coordinator provides types and methods for the coordination of Helium nodes.
// In the current implementation, it only provides the event types constituting the
// event log.
package coordinator

import (
	"fmt"

	"github.com/ChristianMct/helium/circuits"
	"github.com/ChristianMct/helium/protocols"
)

// Event is a type for coordination events in the coordinator.
type Event struct {
	ProtocolEvent *protocols.Event
	CircuitEvent  *circuits.Event // TODO refactor as setup and compute event wrapping protocol events ?
}

// IsProtocolEvent whether the event contains a protocol-related event.
func (ev Event) IsProtocolEvent() bool {
	return ev.ProtocolEvent != nil
}

// IsSetupEvent returns whether the event contains a protocol-related event.
func (ev Event) IsSetupEvent() bool {
	return ev.IsProtocolEvent() && ev.ProtocolEvent.IsSetupEvent()
}

// IsComputeEvent returns whether the event contains a circuit-related event.
func (ev Event) IsComputeEvent() bool {
	return ev.CircuitEvent != nil || (ev.ProtocolEvent != nil && ev.ProtocolEvent.IsComputeEvent())
}

// String returns a string representation of the event.
func (ev Event) String() string {
	switch {
	case ev.IsProtocolEvent():
		return fmt.Sprintf("PROTOCOL %s", ev.ProtocolEvent)
	case ev.IsComputeEvent():
		return fmt.Sprintf("CIRCUIT %s", ev.CircuitEvent)
	default:
		return "UNKNOWN"
	}

}

// Log is a type for a coordinator log.
// A coordinator log is an ordered list of events.
type Log []Event
