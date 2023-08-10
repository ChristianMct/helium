package grpctrans

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/pkg"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func (t *Transport) clientSigner(ctx context.Context, method string, req interface{}, reply interface{},
	cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {

	switch req.(type) { // TODO better way to check with using method field
	case *api.Share, *api.CiphertextRequest, *api.Ciphertext:
		break
	default:
		return invoker(ctx, method, req, reply, cc, opts...)
	}

	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		return fmt.Errorf("invalid outgoing context")
	}

	data, err := t.getSignData(md, req)
	if err != nil {
		return fmt.Errorf("got error: %w", err)
	}

	signature, err := t.Sign(data)
	if err != nil {
		log.Printf("got error: %s\n", err)
	}

	switch req := req.(type) {
	case *api.Share:
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
		signedData, err = t.getSignData(replyMd, reply)
		if err != nil {
			return errorSt
		}
		valid := t.Vfy(signedData, sig, t.tlsSetup.peerPKs[peer])
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
		signedData, err = t.getSignData(replyMd, reply)
		if err != nil {
			return errorSt
		}
		valid := t.Vfy(signedData, sig, t.tlsSetup.peerPKs[peer])
		if !valid {
			log.Println("invalid response :/")
			return errorSt
		}
	default:
		return fmt.Errorf("unhandled response type %T", reply)
	}

	return err
}

// Authorization unary interceptor function to handle authorize per RPC call.
func (t *Transport) serverSigChecker(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	switch req := req.(type) {
	case *api.Share:
		if req.Signature.Type != t.sigs.Type {
			return nil, fmt.Errorf("wrong signature provided, expected %s - got %s",
				t.sigs.Type, req.Signature.Type)
		}
	case *api.Ciphertext:
		if req.Signature.Type != t.sigs.Type {
			return nil, fmt.Errorf("wrong signature provided, expected %s - got %s",
				t.sigs.Type, req.Signature.Type)
		}
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		log.Printf("failed to get metadata")
	}

	data, err := t.getSignData(md, req)
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
	pk := t.tlsSetup.peerPKs[nodeID]

	var valid bool
	switch req := req.(type) {
	case *api.Share:
		valid = t.Vfy(data, req.Signature, pk)
	case *api.HelloRequest, *api.HelloResponse, *api.ProtocolID:
		valid = true
	case *api.CiphertextRequest:
		valid = t.Vfy(data, req.Signature, pk)
	case *api.Ciphertext:
		valid = t.Vfy(data, req.Signature, pk)
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
		replyMd.Append("sender_id", string(t.id))
	} else {
		replyMd.Append("node_id", string(t.id))
	}

	var sig *api.Signature
	switch h := h.(type) {
	case *api.Share:
		data, err = t.getSignData(replyMd, h)
		if err != nil {
			return nil, errorSt
		}
		sig, err = t.Sign(data)
		if err != nil {
			return nil, errorSt
		}
		h.Signature = sig
	case *api.Ciphertext:
		replyMd.Append("circuit_id", md.Get("circuit_id")[0])
		data, err = t.getSignData(replyMd, h)
		if err != nil {
			return nil, errorSt
		}
		sig, err = t.Sign(data)
		if err != nil {
			return nil, errorSt
		}
		h.Signature = sig
	case *api.CiphertextID: // todo - Should be signed?
		break

	case *api.Void, *api.HelloRequest, *api.HelloResponse, *api.AggregationOutput:
		break
	default:
		return nil, fmt.Errorf("unhandled type %T", h)
	}
	return h, err
}

func (t *Transport) Sign(data []byte) (*api.Signature, error) {
	signature := api.Signature{
		Type:   t.sigs.Type,
		Signer: &api.NodeID{NodeId: string(t.id)},
	}

	switch t.sigs.Type {
	case api.SignatureType_NONE:
		signature.Signature = make([]byte, 0)
	case api.SignatureType_ED25519:
		signature.Signature = ed25519.Sign(t.sigs.sk, data)
	default:
		return nil, fmt.Errorf("unknown signature scheme: %s", t.sigs.Type)
	}

	return &signature, nil
}

func (t *Transport) Vfy(msg []byte, sig *api.Signature, pk crypto.PublicKey) bool {
	if t.sigs.Type != sig.Type {
		return false // signature mismatch
	}

	switch sig.Type {
	case api.SignatureType_NONE:
		return true
	case api.SignatureType_ED25519:
		pk, ok := pk.(ed25519.PublicKey)
		if !ok {
			return false
		}
		return ed25519.Verify(pk, msg, sig.Signature)
	}
	return false
}

func (t *Transport) getSignData(md metadata.MD, share interface{}) ([]byte, error) {
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

	if share != nil {
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
				ProtocolID: share.Desc.ProtocolID.ProtocolID,
				Round:      *share.Desc.Round,
				Share:      share.Share,
			}
		case *api.HelloRequest, *api.HelloResponse, *api.ProtocolID:
			break
		default:
			return []byte{}, fmt.Errorf("unknwon share type: %T", share)
		}
	}

	jsonData, err := json.Marshal(signData)
	if err != nil {
		return nil, err
	}
	return jsonData, nil

}
