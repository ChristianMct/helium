package circuits

import (
	"fmt"

	"github.com/ChristianMct/helium"
)

// Event is a type for circuit-related events.
type Event struct {
	EventType
	helium.Descriptor
}

// EventType define the type of event (see circuits.Event)
type EventType int8

const (
	// Completed corresponds to then event of a circuit being completed.
	// It is published by the evaluator.
	Completed EventType = iota
	// Started corresponds to then event of a circuit being started.
	// It is published by the node requesting the evaluation.
	Started
	// Executing corresponds to the event of the evaluator being ready to
	// receive the circuit's inputs. Participants send their inputs only
	// after this event.
	Executing
	// Failed corresponds to then event of a circuit failing to execute to completion.
	Failed
)

var statusToString = []string{"COMPLETED", "STARTED", "EXECUTING", "FAILED"}

func (t EventType) String() string {
	if int(t) >= len(statusToString) || t < 0 {
		return "UNKNOWN"
	}
	return statusToString[t]
}

func (u Event) String() string {
	return fmt.Sprintf("%s: %s", u.EventType, u.Descriptor.HID())
}
