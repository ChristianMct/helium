package centralized

import (
	"context"
	"fmt"

	"github.com/ldsec/helium"
	"google.golang.org/grpc/metadata"
)

type ctxKey string

var (
	ctxSessionID ctxKey = "session_id"
	ctxCircuitID ctxKey = "circuit_id"
)

func newOutgoingContext(senderID *helium.NodeID, sessID *helium.SessionID, circID *helium.CircuitID) context.Context {
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

func getOutgoingContext(ctx context.Context, senderID helium.NodeID) context.Context {
	md := metadata.New(nil)
	md.Append("sender_id", string(senderID))
	if sessID, hasSessID := helium.SessionIDFromContext(ctx); hasSessID {
		md.Append(string(ctxSessionID), string(sessID))
	}
	if circID, hasCircID := helium.CircuitIDFromContext(ctx); hasCircID {
		md.Append(string(ctxCircuitID), string(circID))
	}
	return metadata.NewOutgoingContext(ctx, md)
}

func getContextFromIncomingContext(inctx context.Context) (ctx context.Context, err error) {

	sid := sessionIDFromIncomingContext(inctx)
	if len(sid) == 0 {
		return nil, fmt.Errorf("invalid incoming context: missing session id")
	}

	ctx = context.WithValue(inctx, helium.CtxSessionID, sid)
	cid := circuitIDFromIncomingContext(inctx)
	if len(cid) != 0 {
		ctx = context.WithValue(ctx, helium.CtxCircuitID, cid)
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

func senderIDFromIncomingContext(ctx context.Context) helium.NodeID {
	return helium.NodeID(valueFromIncomingContext(ctx, "sender_id"))
}

func sessionIDFromIncomingContext(ctx context.Context) helium.SessionID {
	return helium.SessionID(valueFromIncomingContext(ctx, string(ctxSessionID)))
}

func circuitIDFromIncomingContext(ctx context.Context) helium.CircuitID {
	return helium.CircuitID(valueFromIncomingContext(ctx, string(ctxCircuitID)))
}
