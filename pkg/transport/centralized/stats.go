package centralized

import (
	"sync"

	"github.com/ldsec/helium/pkg/transport"
	"golang.org/x/net/context"
	"google.golang.org/grpc/stats"
)

type statsHandler struct {
	mu    sync.Mutex
	stats transport.NetStats
}

// TagRPC can attach some information to the given context.
// The context used for the rest lifetime of the RPC will be derived from
// the returned context.
func (s *statsHandler) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context {
	return ctx
}

// HandleRPC processes the RPC stats.
func (s *statsHandler) HandleRPC(_ context.Context, sta stats.RPCStats) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch sta := sta.(type) {
	case *stats.InPayload:
		s.stats.DataRecv += uint64(sta.WireLength)
	case *stats.OutPayload:
		s.stats.DataSent += uint64(sta.WireLength)
	}
}

// TagConn can attach some information to the given context.
// The returned context will be used for stats handling.
// For conn stats handling, the context used in HandleConn for this
// connection will be derived from the context returned.
// For RPC stats handling,
//   - On server side, the context used in HandleRPC for all RPCs on this
//
// connection will be derived from the context returned.
//   - On client side, the context is not derived from the context returned.
func (s *statsHandler) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return ctx
}

// HandleConn processes the Conn stats.
func (s *statsHandler) HandleConn(_ context.Context, _ stats.ConnStats) {}
