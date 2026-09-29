package protocols

import "fmt"

// Event is a type for protocol-execution-related events. Events form the
// coordination log of a session (see Coordinator).
type Event struct {
	EventType
	Descriptor
}

// EventType defines the type of protocol-execution-related events.
type EventType int8

const (
	// Completed is the event type for a completed protocol. It is published by the aggregator.
	Completed EventType = iota
	// Started is the event type for a started protocol. It is published by the coordinator.
	Started
	// Executing is the event type for a protocol whose aggregator is ready to receive shares.
	// It is published by the aggregator; participants send their share only after this event.
	Executing
	// Failed is the event type for a protocol that has failed. It is published by the coordinator.
	Failed
)

var evtypeToString = []string{"COMPLETED", "STARTED", "EXECUTING", "FAILED"}

// String returns the string representation of the event type.
func (t EventType) String() string {
	if int(t) >= len(evtypeToString) || t < 0 {
		return "UNKNOWN"
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
