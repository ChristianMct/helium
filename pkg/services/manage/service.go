package manage

import (
	"log"
	"sync"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/node"
	pkg "github.com/ldsec/helium/pkg/session"
)

type ManageService struct {
	*node.Node

	peers map[pkg.NodeID]api.ManageServiceClient

	Greets sync.WaitGroup
}

func NewManageService(n *node.Node) (s *ManageService) {
	s = new(ManageService)
	s.Node = n
	s.peers = make(map[pkg.NodeID]api.ManageServiceClient)
	if n.HasAddress() {
		NewManageServiceServer(s)
		s.Greets.Add(len(n.Peers()))
	}
	return s
}

func (node *ManageService) Connect() error {
	for peerID, peerConn := range node.Conns() {
		node.peers[peerID] = api.NewManageServiceClient(peerConn)
	}
	return nil
}

// GreetAll greets all the nodes peers.
func (node *ManageService) GreetAll() {
	ctx := node.GetContext("test-session")
	nodeID := node.ID()
	for peerID, peer := range node.peers {
		if peerID != nodeID {
			log.Printf("Node %s | is greeting %s\n", node.ID(), peerID)
			_, err := peer.SayHello(ctx, &api.HelloRequest{})
			if err != nil {
				log.Printf("Node %s | could not greet: %v\n", node.ID(), err)
			}
			log.Printf("Node %s | received greeting response from %s\n", node.ID(), peerID)
		}
	}
}

func (node *ManageService) WaitForGreetings() {
	node.Greets.Wait()
}
