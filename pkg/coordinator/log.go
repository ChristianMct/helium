package coordinator

import (
	"time"

	"github.com/ldsec/helium/pkg/circuits"
	"github.com/ldsec/helium/pkg/protocols"
)

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

type Log []Event
