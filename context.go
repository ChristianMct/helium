package helium

import (
	"context"
	"fmt"

	"github.com/ChristianMct/helium/services"
	"github.com/ChristianMct/helium/session"
	"google.golang.org/grpc/metadata"
)

func getOutgoingContext(ctx context.Context) (context.Context, error) {
	md := metadata.New(nil)

	// required fields
	if sessID, hasSessID := session.IDFromContext(ctx); hasSessID {
		md.Append(string(session.CtxSessionID), string(sessID))
	} else {
		return nil, fmt.Errorf("outgoing context must have a session id")
	}

	if nodeID, hasNodeID := session.NodeIDFromContext(ctx); hasNodeID {
		md.Append(string(session.CtxNodeID), string(nodeID))
	} else {
		return nil, fmt.Errorf("outgoing context must have a node id")
	}

	// optional fields
	if service, hasService := services.ServiceFromContext(ctx); hasService {
		md.Append(string(services.CtxKeyName), service)
	}

	if circID, hasCircID := session.CircuitIDFromContext(ctx); hasCircID {
		md.Append(string(session.CtxCircuitID), string(circID))
	}

	return metadata.NewOutgoingContext(ctx, md), nil
}

func getContextFromIncomingContext(inctx context.Context) (ctx context.Context, err error) {

	sid := sessionIDFromIncomingContext(inctx)
	if len(sid) == 0 {
		return nil, fmt.Errorf("invalid incoming context: missing session id")
	}

	ctx = context.WithValue(inctx, session.CtxSessionID, sid)
	cid := circuitIDFromIncomingContext(inctx)
	if len(cid) != 0 {
		ctx = context.WithValue(ctx, session.CtxCircuitID, cid)
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

func senderIDFromIncomingContext(ctx context.Context) session.NodeID {
	return session.NodeID(valueFromIncomingContext(ctx, string(session.CtxNodeID)))
}

func sessionIDFromIncomingContext(ctx context.Context) session.ID {
	return session.ID(valueFromIncomingContext(ctx, string(session.CtxSessionID)))
}

func circuitIDFromIncomingContext(ctx context.Context) session.CircuitID {
	return session.CircuitID(valueFromIncomingContext(ctx, string(session.CtxCircuitID)))
}
