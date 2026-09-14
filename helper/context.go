package helper

import (
	"context"

	"github.com/ChristianMct/helium"
	"google.golang.org/grpc/metadata"
)

type ctxKeyT string

const (
	// ctxKeyService is the context key (and gRPC metadata key) tagging a request with
	// the phase it belongs to ("setup" or "compute"), for network statistics.
	ctxKeyService ctxKeyT = "service"
	// ctxKeyNodeID is the gRPC metadata key carrying the id of the sending node.
	ctxKeyNodeID ctxKeyT = "node_id"
)

func contextWithService(ctx context.Context, service string) context.Context {
	return context.WithValue(ctx, ctxKeyService, service)
}

func serviceFromContext(ctx context.Context) (string, bool) {
	service, ok := ctx.Value(ctxKeyService).(string)
	return service, ok
}

// outgoingContextWithNodeID returns an outgoing gRPC context carrying the sender's
// node id and, when set, the phase the request belongs to.
func outgoingContextWithNodeID(ctx context.Context, nodeID helium.NodeID) context.Context {
	md := metadata.New(nil)
	md.Append(string(ctxKeyNodeID), string(nodeID))
	if service, hasService := serviceFromContext(ctx); hasService {
		md.Append(string(ctxKeyService), service)
	}
	return metadata.NewOutgoingContext(ctx, md)
}

// senderIDFromIncomingContext returns the id of the node that sent the request.
func senderIDFromIncomingContext(ctx context.Context) helium.NodeID {
	return helium.NodeID(valueFromIncomingContext(ctx, string(ctxKeyNodeID)))
}

func valueFromIncomingContext(ctx context.Context, key string) string {
	md, hasMd := metadata.FromIncomingContext(ctx)
	if !hasMd {
		return ""
	}
	vals := md.Get(key)
	if len(vals) < 1 {
		return ""
	}
	return vals[0]
}
