package grpctrans

import (
	"context"
	"fmt"
	"log"

	"github.com/ldsec/helium/pkg"
	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/transport"
	"google.golang.org/grpc"
)

type computeTransport struct {
	*Transport
	*ShareTransport

	api.UnimplementedComputeServiceServer

	srvHandler transport.ComputeServiceHandler

	peers map[pkg.NodeID]api.ComputeServiceClient
}

func (t *Transport) newComputeTransport() *computeTransport {
	pc := new(computeTransport)
	pc.Transport = t
	pc.ShareTransport = t.NewShareTransport()

	pc.peers = make(map[pkg.NodeID]api.ComputeServiceClient)
	for _, peer := range t.nodeList {
		pc.peers[peer.NodeID] = nil
	}

	return pc
}

func (env *computeTransport) registerService(srv transport.ComputeServiceHandler) {
	env.srvHandler = srv
}

func (env *computeTransport) connect() {
	env.ShareTransport.Run()

	peerClis := make(map[pkg.NodeID]ShareTransportClient)
	for peerID, peerConn := range env.conns {
		peerCli := api.NewComputeServiceClient(peerConn)
		env.peers[peerID] = peerCli
		peerClis[peerID] = &computeServiceClientWrapper{peerCli}
	}
	err := env.ShareTransport.Connect(peerClis)
	if err != nil {
		panic(err)
	}
}

func (env *computeTransport) GetCiphertext(ctx context.Context, ctID pkg.CiphertextID) (*pkg.Ciphertext, error) {
	ctURL, err := pkg.ParseURL(string(ctID))
	if err != nil {
		return nil, err
	}

	host := ctURL.NodeID()
	if host == "" {
		return nil, fmt.Errorf("ciphertext id is local id")
	}

	peer, exists := env.peers[host]
	if !exists {
		return nil, fmt.Errorf("peer with id %s does not exist", host)
	}

	// DEBUG
	//log.Printf("[GetCipherText] fetching ctID %v, host: %v, peer: %v", ctID, host, peer)

	if peer == nil {
		return nil, fmt.Errorf("peer with id %s is a light node", host)
	}

	outCtx := pkg.GetOutgoingContext(ctx, env.id)
	apiCt, err := peer.GetCiphertext(outCtx, &api.CiphertextRequest{Id: ctID.ToGRPC()})
	if err != nil {
		return nil, err
	}
	return pkg.NewCiphertextFromGRPC(apiCt)
}

func (env *computeTransport) PutCiphertext(ctx context.Context, nodeID pkg.NodeID, ct pkg.Ciphertext) error {
	if nodeID == env.id {
		return env.srvHandler.PutCiphertext(ctx, ct)
	}
	peerCli, exists := env.peers[nodeID]
	if !exists {
		panic(fmt.Errorf("not connected to party %s", nodeID))
	}
	ctx = pkg.GetOutgoingContext(ctx, env.id)
	_, err := peerCli.PutCiphertext(ctx, ct.ToGRPC())
	if err != nil {
		log.Printf("error while sending ciphertext: %s", err)
	}
	return nil
}

type ComputeTransportHandler struct {
	*computeTransport
}

func (env *ComputeTransportHandler) GetCiphertext(ctx context.Context, ctr *api.CiphertextRequest) (*api.Ciphertext, error) {
	ct, err := env.srvHandler.GetCiphertext(ctx, pkg.CiphertextID(ctr.Id.CiphertextId))
	if err != nil {
		return nil, err
	}
	return ct.ToGRPC(), nil
}

func (env *ComputeTransportHandler) PutCiphertext(ctx context.Context, apict *api.Ciphertext) (*api.CiphertextID, error) {
	ct, err := pkg.NewCiphertextFromGRPC(apict)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext: %w", err)
	}
	err = env.srvHandler.PutCiphertext(ctx, *ct)
	if err != nil {
		return nil, err
	}
	return ct.ID.ToGRPC(), nil
}

func (env *computeTransport) PutShare(ctx context.Context, share *api.Share) (*api.Void, error) {
	return env.ShareTransport.PutShare(ctx, share)
}

func (env *computeTransport) StreamShares(stream api.ComputeService_StreamSharesServer) error {
	return env.ShareTransport.StreamShares(stream)
}

type computeServiceClientWrapper struct {
	api.ComputeServiceClient
}

func (scw *computeServiceClientWrapper) StreamShares(ctx context.Context, opts ...grpc.CallOption) (ShareStreamClient, error) {
	return scw.ComputeServiceClient.StreamShares(ctx, opts...)
}
