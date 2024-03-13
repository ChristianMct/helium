package centralized

import (
	"context"
	"fmt"

	"github.com/ldsec/helium/pkg"
	"google.golang.org/grpc/metadata"
)

type ctxKey string

var (
	ctxSessionID ctxKey = "session_id"
	ctxCircuitID ctxKey = "circuit_id"
)

func newOutgoingContext(senderID *pkg.NodeID, sessID *pkg.SessionID, circID *pkg.CircuitID) context.Context {
	md := metadata.New(nil)
	if senderID != nil {
		md.Append("sender_id", string(*senderID))
	}
	if sessID != nil {
		md.Append(string(ctxSessionID), string(*sessID))
	}
	if circID != nil {
		md.Append(string(ctxCircuitID), string(*circID))
	}
	return metadata.NewOutgoingContext(context.Background(), md)
}

func getOutgoingContext(ctx context.Context, senderID pkg.NodeID) context.Context {
	md := metadata.New(nil)
	md.Append("sender_id", string(senderID))
	if sessID, hasSessID := pkg.SessionIDFromContext(ctx); hasSessID {
		md.Append(string(ctxSessionID), string(sessID))
	}
	if circID, hasCircID := pkg.CircuitIDFromContext(ctx); hasCircID {
		md.Append(string(ctxCircuitID), string(circID))
	}
	return metadata.NewOutgoingContext(ctx, md)
}

func getContextFromIncomingContext(inctx context.Context) (ctx context.Context, err error) {

	sid := sessionIDFromIncomingContext(inctx)
	if len(sid) == 0 {
		return nil, fmt.Errorf("invalid incoming context: missing session id")
	}

	ctx = context.WithValue(inctx, pkg.CtxSessionID, sid)
	cid := circuitIDFromIncomingContext(inctx)
	if len(cid) != 0 {
		ctx = context.WithValue(ctx, pkg.CtxCircuitID, cid)
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

func senderIDFromIncomingContext(ctx context.Context) pkg.NodeID {
	return pkg.NodeID(valueFromIncomingContext(ctx, "sender_id"))
}

func sessionIDFromIncomingContext(ctx context.Context) pkg.SessionID {
	return pkg.SessionID(valueFromIncomingContext(ctx, string(ctxSessionID)))
}

func circuitIDFromIncomingContext(ctx context.Context) pkg.CircuitID {
	return pkg.CircuitID(valueFromIncomingContext(ctx, string(ctxCircuitID)))
}
