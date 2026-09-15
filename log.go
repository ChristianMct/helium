package helium

import (
	"context"
	"errors"
	"slices"
	"sync"
)

// ErrLogClosed is returned when appending to a closed log.
var ErrLogClosed = errors.New("log is closed")

// Log is an append-only log of events of type T that can be subscribed to.
// Subscribers receive the events appended before their registration as a
// slice (catch-up), and the following ones through a channel. Each subscriber
// is served by its own goroutine, so a slow subscriber never blocks the log.
// Log is safe for concurrent use.
type Log[T any] struct {
	mu     sync.Mutex
	cond   *sync.Cond
	events []T
	closed bool
}

// NewLog creates a new, empty, open log.
func NewLog[T any]() *Log[T] {
	l := &Log[T]{}
	l.cond = sync.NewCond(&l.mu)
	return l
}

// Append appends the events to the log. It returns ErrLogClosed if the log is closed.
func (l *Log[T]) Append(evs ...T) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrLogClosed
	}
	l.events = append(l.events, evs...)
	l.cond.Broadcast()
	return nil
}

// Register subscribes to the log. It returns a copy of the events appended so far,
// and a channel delivering the following ones. The channel is closed once the log
// is closed and all events have been delivered, or when ctx is cancelled.
func (l *Log[T]) Register(ctx context.Context) (past []T, live <-chan T) {
	l.mu.Lock()
	defer l.mu.Unlock()
	past = slices.Clone(l.events)
	ch := make(chan T)
	if l.closed {
		close(ch)
		return past, ch
	}
	go l.forward(ctx, len(l.events), ch)
	return past, ch
}

// forward sends the events from cursor onward to live, and closes it when the log
// is closed and fully delivered, or when ctx is cancelled.
func (l *Log[T]) forward(ctx context.Context, cursor int, live chan<- T) {
	defer close(live)
	stop := context.AfterFunc(ctx, func() {
		l.mu.Lock()
		l.cond.Broadcast()
		l.mu.Unlock()
	})
	defer stop()
	for {
		l.mu.Lock()
		for cursor == len(l.events) && !l.closed && ctx.Err() == nil {
			l.cond.Wait()
		}
		if ctx.Err() != nil || cursor == len(l.events) { // cancelled, or closed and drained
			l.mu.Unlock()
			return
		}
		ev := l.events[cursor]
		cursor++
		l.mu.Unlock()

		select {
		case live <- ev:
		case <-ctx.Done():
			return
		}
	}
}

// Close closes the log: no more events can be appended, and the subscribers'
// channels are closed once they have received all events. Close is idempotent.
func (l *Log[T]) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	l.cond.Broadcast()
}

// Closed returns whether the log is closed.
func (l *Log[T]) Closed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed
}

// Events returns a copy of the events in the log.
func (l *Log[T]) Events() []T {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.events)
}

// Len returns the number of events in the log.
func (l *Log[T]) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.events)
}
