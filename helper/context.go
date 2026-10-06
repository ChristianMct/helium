package helper

import (
	"context"
	"fmt"

	"github.com/ChristianMct/helium"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
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

// authenticatedNodeID returns the node id of the peer that opened the connection the
// request arrived on, as certified by the mTLS handshake: the single dNSName SAN of
// the CA-verified client certificate that names a node of nl.
//
// The identity is bound to the channel, not to the message. This is sufficient in the
// helper-assisted setting because every attributed object (a share, an input operand)
// reaches the helper directly from the node that produced it, over that node's own
// connection. Relaying attributed objects between peers, or a threat model in which
// the helper is actively malicious rather than honest-but-curious, would call for
// message-level signatures instead.
func authenticatedNodeID(ctx context.Context, nl helium.NodeList) (helium.NodeID, error) {
	p, hasPeer := peer.FromContext(ctx)
	if !hasPeer {
		return "", fmt.Errorf("no peer information in context")
	}

	tlsInfo, isTLS := p.AuthInfo.(credentials.TLSInfo)
	if !isTLS {
		return "", fmt.Errorf("connection is not authenticated with TLS")
	}

	// the verified chains, not the peer certificates: only the former have been
	// checked against the CA, and they are populated only under
	// tls.RequireAndVerifyClientCert (see TLSConfig.serverCredentials).
	chains := tlsInfo.State.VerifiedChains
	if len(chains) == 0 || len(chains[0]) == 0 {
		return "", fmt.Errorf("no verified certificate chain for the peer")
	}
	leaf := chains[0][0]

	var ids []helium.NodeID
	for _, name := range leaf.DNSNames {
		if id := helium.NodeID(name); nl.Contains(id) {
			ids = append(ids, id)
		}
	}
	switch len(ids) {
	case 1:
		return ids[0], nil
	case 0:
		return "", fmt.Errorf("the peer certificate names no known node (SANs: %v)", leaf.DNSNames)
	default:
		return "", fmt.Errorf("the peer certificate names several known nodes: %v", ids)
	}
}

// outgoingContextWithNodeID returns an outgoing gRPC context carrying the sender's
// node id and, when set, the phase the request belongs to. The node id is a plain
// self-assertion: it is only trusted when TLS is disabled (see TLSConfig).
func outgoingContextWithNodeID(ctx context.Context, nodeID helium.NodeID) context.Context {
	md := metadata.New(nil)
	md.Append(string(ctxKeyNodeID), string(nodeID))
	if service, hasService := serviceFromContext(ctx); hasService {
		md.Append(string(ctxKeyService), service)
	}
	return metadata.NewOutgoingContext(ctx, md)
}

// unauthenticatedNodeIDFromMetadata returns the node id the sender claims in the
// request metadata. The value is unauthenticated and must only be used when TLS is
// disabled (see TLSConfig.InsecureChannels and Server.callerID).
func unauthenticatedNodeIDFromMetadata(ctx context.Context) helium.NodeID {
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
