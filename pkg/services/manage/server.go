package manage

import (
	"context"
	"fmt"
	"log"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/node"
	pkg "github.com/ldsec/helium/pkg/session"
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

	ictx := node.Context{C: ctx}
	log.Printf("Node %s | received greeting from %s\n", mss.ID(), ictx.SenderID())

	if mss.ID() == pkg.NodeID(ictx.SenderID()) {
		return nil, fmt.Errorf("node should not greet itself %s == %s", mss.ID(), pkg.NodeID(ictx.SenderID()))
	}

	mss.Greets.Done()

	return &api.HelloResponse{}, nil
}
