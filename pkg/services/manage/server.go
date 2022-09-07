package manage

import (
	"context"
	"helium/pkg/api"
	"helium/pkg/node"
	pkg "helium/pkg/session"
	"log"
)

type ManageServiceServer struct {
	*ManageService
	api.UnimplementedManageServiceServer
}

func NewManageServiceServer(ms *ManageService) *ManageServiceServer {
	mss := new(ManageServiceServer)
	mss.ManageService = ms
	ms.RegisterService(&api.ManageService_ServiceDesc, mss)
	return mss
}

/*
SayHello - hello from one node to another

node : Node to which we are sending hello
in : P2PRequest from sending node
ctx : context

returns P2PResponse from node to the in P2PRequest from another node
*/
func (mss *ManageServiceServer) SayHello(ctx context.Context, in *api.HelloRequest) (*api.HelloResponse, error) {
	defer mss.Greets.Done()

	ictx := node.Context{C: ctx}

	if mss.ID() == pkg.NodeID(ictx.SenderID()) {
		log.Fatal("should not great itself")
	}

	log.Printf("Node %s | received greeting from %s\n", mss.ID(), ictx.SenderID())
	return &api.HelloResponse{}, nil
}
