package helper

import (
	"context"
	"fmt"
	"sync"

	"github.com/ChristianMct/helium/utils"
	"google.golang.org/grpc/stats"
)

// ServiceStats contains the network statistics of a connection.
type ServiceStats struct {
	DataSent, DataRecv uint64
}

// String returns a string representation of the network statistics.
func (s ServiceStats) String() string {
	return fmt.Sprintf("Sent: %s, Received: %s", utils.ByteCountSI(s.DataSent), utils.ByteCountSI(s.DataRecv))
}

// NetStats contains the network statistics of a node, per phase.
type NetStats struct {
	Setup, Compute, Others ServiceStats
}

func (ns NetStats) String() string {
	return fmt.Sprintf("NetStats:\n\tSetup: %s\n\tCompute: %s\n\tOthers: %s", ns.Setup, ns.Compute, ns.Others)
}

type statsHandler struct {
	mu sync.Mutex
	NetStats
}

// TagRPC can attach some information to the given context.
// The context used for the rest lifetime of the RPC will be derived from
// the returned context.
func (s *statsHandler) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context {
	if service := valueFromIncomingContext(ctx, string(ctxKeyService)); service != "" {
		ctx = contextWithService(ctx, service)
	}
	return ctx
}

// HandleRPC processes the RPC stats.
func (s *statsHandler) HandleRPC(ctx context.Context, sta stats.RPCStats) {

	var ns *ServiceStats
	service, _ := serviceFromContext(ctx)
	switch service {
	case "setup":
		ns = &s.Setup
	case "compute":
		ns = &s.Compute
	default:
		ns = &s.Others
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	switch sta := sta.(type) {
	case *stats.InPayload:
		ns.DataRecv += uint64(sta.WireLength)
	case *stats.OutPayload:
		ns.DataSent += uint64(sta.WireLength)
	}
}

// TagConn can attach some information to the given context.
func (s *statsHandler) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return ctx
}

// HandleConn processes the Conn stats.
func (s *statsHandler) HandleConn(_ context.Context, _ stats.ConnStats) {}

// GetStats returns the network statistics.
func (s *statsHandler) GetStats() NetStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.NetStats
}
