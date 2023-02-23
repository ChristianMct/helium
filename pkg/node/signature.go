package node

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log"

	"github.com/ldsec/helium/pkg/api"
	pkg "github.com/ldsec/helium/pkg/session"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func (node *Node) clientSigner(ctx context.Context, method string, req interface{}, reply interface{},
	cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	//start := time.Now()

	md, ok := metadata.FromOutgoingContext(ctx)

	if !ok {
		panic("failed casting :/")
	}

	data, err := node.getSignData(md, req)
	if err != nil {
		return fmt.Errorf("got error: %w", err)
	}

	signature, err := node.Sign(data)
	if err != nil {
		log.Printf("got error: %s\n", err)
	}

	switch req := req.(type) {
	case *api.Share:
		req.Signature = signature
	case *api.ShareRequest:
		req.Signature = signature
	case *api.CiphertextRequest:
		req.Signature = signature
	case *api.Ciphertext:
		req.Signature = signature
	}

	// Calls the invoker to execute RPC
	err = invoker(ctx, method, req, reply, cc, opts...)
	// Logic after invoking the invoker

	errorSt := status.New(codes.Canceled, "couldn't vfy reply").Err()
	var signedData []byte
	switch reply := reply.(type) {
	case *api.Void, *api.HelloRequest, *api.HelloResponse, *api.CiphertextID:
		break
	case *api.Share:
		sig, peer := reply.Signature, pkg.NodeID(reply.Signature.Signer.NodeId)
		replyMd := metadata.New(map[string]string{
			"session_id": md.Get("session_id")[0],
			"sender_id":  string(peer),
		})
		signedData, err = node.getSignData(replyMd, reply)
		if err != nil {
			return errorSt
		}
		valid := node.Vfy(signedData, sig, node.tlsSetup.peerPKs[peer])
		if !valid {
			log.Println("invalid response :/")
			return errorSt
		}
	case *api.Ciphertext:
		sig, peer := reply.Signature, pkg.NodeID(reply.Signature.Signer.NodeId)
		replyMd := metadata.New(map[string]string{
			"session_id": md.Get("session_id")[0],
			"sender_id":  string(peer),
			"circuit_id": md.Get("circuit_id")[0],
		})
		signedData, err = node.getSignData(replyMd, reply)
		if err != nil {
			return errorSt
		}
		valid := node.Vfy(signedData, sig, node.tlsSetup.peerPKs[peer])
		if !valid {
			log.Println("invalid response :/")
			return errorSt
		}
	default:
		return fmt.Errorf("unhandled response type %T", reply)
	}

	//log.Printf("Node %s | Invoked RPC method=%s; Duration=%s; Error=%v\n", node.id, method, time.Since(start), err)
	return err
}

// Authorization unary interceptor function to handle authorize per RPC call.
func (node *Node) serverSigChecker(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	switch req := req.(type) {
	case *api.Share:
		if req.Signature.Type != node.sigs.Type {
			return nil, fmt.Errorf("wrong signature provided, expected %s - got %s",
				node.sigs.Type, req.Signature.Type)
		}
	case *api.ShareRequest:
		if req.Signature.Type != node.sigs.Type {
			return nil, fmt.Errorf("wrong signature provided, expected %s - got %s",
				node.sigs.Type, req.Signature.Type)
		}
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		log.Printf("failed to get metadata")
	}

	data, err := node.getSignData(md, req)
	if err != nil {
		log.Printf("failed to marshall data")
	}

	var nodeID pkg.NodeID

	// todo - why rename to sender_id ? not sure why it isn't consistent :/
	if len(md.Get("sender_id")) > 0 {
		nodeID = pkg.NodeID(md.Get("sender_id")[0])
	} else {
		nodeID = pkg.NodeID(md.Get("node_id")[0])
	}
	pk := node.tlsSetup.peerPKs[nodeID]

	var valid bool
	switch req := req.(type) {
	case *api.Share:
		valid = node.Vfy(data, req.Signature, pk)
	case *api.ShareRequest:
		valid = node.Vfy(data, req.Signature, pk)
	case *api.HelloRequest, *api.HelloResponse:
		valid = true
	case *api.CiphertextRequest:
		valid = node.Vfy(data, req.Signature, pk)
	case *api.Ciphertext:
		valid = node.Vfy(data, req.Signature, pk)
	}

	if !valid {
		return nil, fmt.Errorf("invalid signature")
	}
	// Calls the handler
	h, err := handler(ctx, req)

	// todo H is the server response - sign before giving it back
	errorSt := status.New(codes.Canceled, "couldn't sign reply").Err()

	replyMd := metadata.New(map[string]string{
		"session_id": md.Get("session_id")[0],
	})

	// todo - why rename to sender_id ? not sure why it isn't consistent :/
	if len(md.Get("session_id")) > 0 {
		replyMd.Append("sender_id", string(node.ID()))
	} else {
		replyMd.Append("node_id", string(node.ID()))
	}

	var sig *api.Signature
	switch h := h.(type) {
	case *api.Share:
		data, err = node.getSignData(replyMd, h)
		if err != nil {
			return nil, errorSt
		}
		sig, err = node.Sign(data)
		if err != nil {
			return nil, errorSt
		}
		h.Signature = sig
	case *api.Ciphertext:
		replyMd.Append("circuit_id", md.Get("circuit_id")[0])
		data, err = node.getSignData(replyMd, h)
		if err != nil {
			return nil, errorSt
		}
		sig, err = node.Sign(data)
		if err != nil {
			return nil, errorSt
		}
		h.Signature = sig
	case *api.CiphertextID: // todo - Should be signed?
		break

	case *api.Void, *api.HelloRequest, *api.HelloResponse:
		break
	default:
		return nil, fmt.Errorf("unhandled type %T", h)
	}
	return h, err
}

func (node *Node) Sign(data []byte) (*api.Signature, error) {
	signature := api.Signature{
		Type:   node.sigs.Type,
		Signer: &api.NodeID{NodeId: string(node.ID())},
	}

	switch node.sigs.Type {
	case api.SignatureType_NONE:
		signature.Signature = make([]byte, 0)
	case api.SignatureType_ED25519:
		signature.Signature = ed25519.Sign(node.sigs.sk, data)
	default:
		return nil, fmt.Errorf("unknown signature scheme: %s", node.sigs.Type)
	}

	return &signature, nil
}

func (node *Node) Vfy(msg []byte, sig *api.Signature, pk crypto.PublicKey) bool {
	if node.sigs.Type != sig.Type {
		return false // signature mismatch
	}

	switch sig.Type {
	case api.SignatureType_NONE:
		return true
	case api.SignatureType_ED25519:
		pk := pk.(ed25519.PublicKey)
		return ed25519.Verify(pk, msg, sig.Signature)
	}
	return false
}

func (node *Node) getSignData(md metadata.MD, share interface{}) ([]byte, error) {
	// todo - why rename to sender_id ? not sure why it isn't consistent :/
	metaFields := metadata.New(map[string]string{
		"session_id": md.Get("session_id")[0],
	})
	if len(md.Get("node_id")) > 0 {
		metaFields.Append("node_id", md.Get("node_id")[0])
	} else {
		metaFields.Append("sender_id", md.Get("sender_id")[0])
	}

	var signData interface{}

	switch share := share.(type) {
	case *api.CiphertextRequest:
		metaFields.Append("circuit_id", md.Get("circuit_id")[0])
		signData = struct {
			NodeID       pkg.NodeID
			Metadata     metadata.MD
			CiphertextID pkg.CiphertextID
		}{
			NodeID:       pkg.NodeID(md.Get("sender_id")[0]),
			Metadata:     metaFields,
			CiphertextID: pkg.CiphertextID(share.Id.String()),
		}
	case *api.Ciphertext:
		metaFields.Append("circuit_id", md.Get("circuit_id")[0])
		signData = struct {
			NodeID       pkg.NodeID
			Metadata     metadata.MD
			CiphertextMD pkg.CiphertextMetadata
			Ciphertext   []byte
		}{
			NodeID:   pkg.NodeID(md.Get("sender_id")[0]),
			Metadata: metaFields,
			CiphertextMD: pkg.CiphertextMetadata{
				ID:   pkg.CiphertextID(share.Metadata.Id.String()),
				Type: pkg.CiphertextType(share.Metadata.Type.Number()),
			},
			Ciphertext: share.Ciphertext,
		}
	case *api.Share:
		signData = struct {
			NodeID     pkg.NodeID
			Metadata   metadata.MD
			ProtocolID string
			Round      uint64
			Share      []byte
		}{
			NodeID:     pkg.NodeID(md.Get("sender_id")[0]),
			Metadata:   metaFields,
			ProtocolID: share.ProtocolID.ProtocolID,
			Round:      *share.Round,
			Share:      share.Share,
		}

	case *api.ShareRequest:
		aggregates := make([]pkg.NodeID, 0)
		for _, a := range share.AggregateFor {
			aggregates = append(aggregates, pkg.NodeID(a.NodeId))
		}
		prev := make([]byte, 0)
		if share.Previous != nil {
			prev = share.Previous.Share
		}

		signData = struct {
			NodeID       pkg.NodeID
			Metadata     metadata.MD
			ProtocolID   string
			Round        uint64
			Previous     []byte
			AggregateFor []pkg.NodeID
		}{
			NodeID:       pkg.NodeID(md.Get("sender_id")[0]),
			Metadata:     metaFields,
			ProtocolID:   share.ProtocolID.ProtocolID,
			Round:        *share.Round,
			Previous:     prev,
			AggregateFor: aggregates,
		}
	case *api.HelloRequest, *api.HelloResponse:
		break
	default:
		return []byte{}, fmt.Errorf("unknwon share type: %T", share)
	}

	jsonData, err := json.Marshal(signData)
	if err != nil {
		return nil, err
	}
	return jsonData, nil

}
