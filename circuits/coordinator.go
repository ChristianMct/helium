package circuits

import (
	"context"
	"fmt"
	"github.com/ChristianMct/helium"

	"github.com/ChristianMct/helium/coordinator"
)

// Coordinator is the interface through which an Engine is driven. It mirrors
// protocols.Coordinator for circuit events: the node requesting an evaluation
// publishes Started, the evaluator's engine publishes Executing, Completed and Failed.
type Coordinator interface {
	// Register subscribes to the circuit events: past holds the events emitted before the
	// registration (catch-up), live delivers the following ones and is closed when
	// coordination ends.
	Register(ctx context.Context) (past []Event, live <-chan Event, err error)
	// Publish appends a circuit event to the coordination log.
	Publish(ctx context.Context, ev Event) error
}

// LogCoordinator is a Coordinator backed by an in-memory coordinator.Log.
type LogCoordinator struct {
	*coordinator.Log[Event]
}

// NewLogCoordinator creates a LogCoordinator over a new log.
func NewLogCoordinator() *LogCoordinator {
	return &LogCoordinator{Log: coordinator.NewLog[Event]()}
}

// Register implements Coordinator.
func (lc *LogCoordinator) Register(ctx context.Context) (past []Event, live <-chan Event, err error) {
	past, live = lc.Log.Register(ctx)
	return past, live, nil
}

// Publish implements Coordinator.
func (lc *LogCoordinator) Publish(_ context.Context, ev Event) error {
	return lc.Log.Append(ev)
}

// Start requests the evaluation of the circuit described by cd, by publishing its Started event.
func (lc *LogCoordinator) Start(ctx context.Context, cd helium.Descriptor) error {
	if len(cd.CircuitID) == 0 {
		return fmt.Errorf("circuit descriptor has no id")
	}
	return lc.Publish(ctx, Event{EventType: Started, Descriptor: cd})
}
