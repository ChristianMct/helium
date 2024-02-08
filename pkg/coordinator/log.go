package coordinator

import (
	"context"
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

type CircuitEvent struct {
	EventType
	circuits.Signature
}

type Event struct {
	time.Time
	*ProtocolEvent
	*CircuitEvent
}

func (ev Event) IsProtocolEvent() bool {
	return ev.ProtocolEvent != nil
}

func (ev Event) IsSetupEvent() bool {
	return !ev.IsComputeEvent()
}

func (ev Event) IsComputeEvent() bool {
	return ev.CircuitEvent != nil
}

type Log []Event
