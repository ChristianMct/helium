package coordinator

import (
	"context"
	"fmt"
	"time"

	"github.com/ldsec/helium/pkg/circuits"
	"github.com/ldsec/helium/pkg/protocols"
)

type Coordinator interface {
	Register(context.Context) (events <-chan Event, present int, err error)
}

type EventType int32

const (
	Completed EventType = iota
	Started
	Executing
	Failed
)

type ProtocolEvent struct {
	EventType
	protocols.Descriptor
}

type Event struct {
	time.Time
	ProtocolEvent *protocols.Event
	CircuitEvent  *circuits.Event
}

func (ev Event) IsProtocolEvent() bool {
	return ev.ProtocolEvent != nil
}

func (ev Event) IsSetupEvent() bool {
	return ev.IsProtocolEvent() && ev.ProtocolEvent.IsSetupEvent()
}

func (ev Event) IsComputeEvent() bool {
	return ev.CircuitEvent != nil || (ev.ProtocolEvent != nil && ev.ProtocolEvent.IsComputeEvent())
}

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

type Log []Event
