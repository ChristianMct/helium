package helium

import (
	"context"
	"fmt"

	"github.com/ChristianMct/helium/services"
	"github.com/ChristianMct/helium/sessions"
	"google.golang.org/grpc/metadata"
)

func getOutgoingContext(ctx context.Context) (context.Context, error) {
	md := metadata.New(nil)

	// required fields
	if sessID, hasSessID := sessions.IDFromContext(ctx); hasSessID {
		md.Append(string(sessions.CtxSessionID), string(sessID))
	} else {
		return nil, fmt.Errorf("outgoing context must have a session id")
	}

	if nodeID, hasNodeID := sessions.NodeIDFromContext(ctx); hasNodeID {
		md.Append(string(sessions.CtxNodeID), string(nodeID))
	} else {
		return nil, fmt.Errorf("outgoing context must have a node id")
	}

	// optional fields
	if service, hasService := services.ServiceFromContext(ctx); hasService {
		md.Append(string(services.CtxKeyName), service)
	}

	if circID, hasCircID := sessions.CircuitIDFromContext(ctx); hasCircID {
		md.Append(string(sessions.CtxCircuitID), string(circID))
	}

	return metadata.NewOutgoingContext(ctx, md), nil
}

func getContextFromIncomingContext(inctx context.Context) (ctx context.Context, err error) {

	sid := sessionIDFromIncomingContext(inctx)
	if len(sid) == 0 {
		return nil, fmt.Errorf("invalid incoming context: missing session id")
	}

	ctx = context.WithValue(inctx, sessions.CtxSessionID, sid)
	cid := circuitIDFromIncomingContext(inctx)
	if len(cid) != 0 {
		ctx = context.WithValue(ctx, sessions.CtxCircuitID, cid)
	}
	return
}

func valueFromIncomingContext(ctx context.Context, key string) string {
	md, hasMd := metadata.FromIncomingContext(ctx)
	if !hasMd {
		return ""
	}
	id := md.Get(key)
	if len(id) < 1 {
		return ""
	}
	return id[0]
}

func senderIDFromIncomingContext(ctx context.Context) sessions.NodeID {
	return sessions.NodeID(valueFromIncomingContext(ctx, string(sessions.CtxNodeID)))
}

func sessionIDFromIncomingContext(ctx context.Context) sessions.ID {
	return sessions.ID(valueFromIncomingContext(ctx, string(sessions.CtxSessionID)))
}

func circuitIDFromIncomingContext(ctx context.Context) sessions.CircuitID {
	return sessions.CircuitID(valueFromIncomingContext(ctx, string(sessions.CtxCircuitID)))
}
