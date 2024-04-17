package centralized

import (
	"context"
	"fmt"

	"github.com/ChristianMct/helium/session"
	"google.golang.org/grpc/metadata"
)

type ctxKey string

var (
	ctxSessionID ctxKey = "session_id"
	ctxCircuitID ctxKey = "circuit_id"
)

func getOutgoingContext(ctx context.Context, senderID session.NodeID) context.Context {
	md := metadata.New(nil)
	md.Append("sender_id", string(senderID))
	if sessID, hasSessID := session.SessionIDFromContext(ctx); hasSessID {
		md.Append(string(ctxSessionID), string(sessID))
	}
	if circID, hasCircID := session.CircuitIDFromContext(ctx); hasCircID {
		md.Append(string(ctxCircuitID), string(circID))
	}
	return metadata.NewOutgoingContext(ctx, md)
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
	return session.NodeID(valueFromIncomingContext(ctx, "sender_id"))
}

func sessionIDFromIncomingContext(ctx context.Context) session.SessionID {
	return session.SessionID(valueFromIncomingContext(ctx, string(ctxSessionID)))
}

func circuitIDFromIncomingContext(ctx context.Context) session.CircuitID {
	return session.CircuitID(valueFromIncomingContext(ctx, string(ctxCircuitID)))
}
