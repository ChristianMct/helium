package manage

import (
	"helium/pkg/api"
	"helium/pkg/node"
	pkg "helium/pkg/session"
	"log"
	"sync"
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
		s.Greets.Add(len(n.Peers()) - 1)
	}
	return s
}

func (s *ManageService) Connect() error {
	for peerID, peerConn := range s.Conns() {
		s.peers[peerID] = api.NewManageServiceClient(peerConn)
	}
	return nil
}

// GreetAll greets all the nodes peers
func (node *ManageService) GreetAll() {
	ctx := node.GetContext("test-session")
	for peerId, peer := range node.peers {
		if peerId != node.ID() {
			log.Printf("Node %s | is greeting %s\n", node.ID(), peerId)
			_, err := peer.SayHello(ctx, &api.HelloRequest{})
			if err != nil {
				log.Printf("Node %s | could not greet: %v\n", node.ID(), err)
			}
			log.Printf("Node %s | received greeting response from %s\n", node.ID(), peerId)
		}
	}
}

func (node *ManageService) WaitForGreetings() {
	node.Greets.Wait()
}
