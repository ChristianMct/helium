package coordinator

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func recv[T any](t *testing.T, ch <-chan T) (v T, more bool) {
	t.Helper()
	select {
	case v, more = <-ch:
		return v, more
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
		return v, false
	}
}

func TestLog(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	l := NewLog[int]()
	require.NoError(t, l.Append(1, 2))

	past, live := l.Register(ctx)
	require.Equal(t, []int{1, 2}, past)

	require.NoError(t, l.Append(3))
	v, more := recv(t, live)
	require.True(t, more)
	require.Equal(t, 3, v)

	// a second subscriber sees the whole past
	past2, live2 := l.Register(ctx)
	require.Equal(t, []int{1, 2, 3}, past2)
	require.Equal(t, 3, l.Len())

	// a cancelled subscriber is released
	subCtx, subCancel := context.WithCancel(ctx)
	_, live3 := l.Register(subCtx)
	subCancel()
	_, more = recv(t, live3)
	require.False(t, more)

	// close: remaining events are delivered, then the channels are closed
	require.NoError(t, l.Append(4))
	l.Close()
	l.Close() // idempotent
	require.ErrorIs(t, l.Append(5), ErrLogClosed)
	require.True(t, l.Closed())
	for _, ch := range []<-chan int{live, live2} {
		v, more = recv(t, ch)
		require.True(t, more)
		require.Equal(t, 4, v)
		_, more = recv(t, ch)
		require.False(t, more)
	}

	// registering on a closed log returns the whole past and a closed channel
	past4, live4 := l.Register(ctx)
	require.Equal(t, []int{1, 2, 3, 4}, past4)
	_, more = recv(t, live4)
	require.False(t, more)
	require.Equal(t, past4, l.Events())
}
