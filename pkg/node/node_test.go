package node_test

import (
	"fmt"
	"helium/pkg/node"
	"helium/pkg/services/manage"
	pkg "helium/pkg/session"
	"strconv"
	"sync"
	"testing"
	"time"
)

type TestConfig struct {
	fullNodes  int
	lightNodes int
	baseAddr   int
}

type Test struct {
	nodes      []*node.Node
	fullNodes  []*node.Node
	lightNodes []*node.Node
}

func genNodeConfigs(config TestConfig) []node.NodeConfig {
	ncs := make([]node.NodeConfig, config.fullNodes+config.lightNodes)
	for i := range ncs {
		ncs[i].ID = pkg.NodeID("light-" + strconv.Itoa(i))
		ncs[i].Peers = make(map[pkg.NodeID]pkg.NodeAddress)
		if i < config.fullNodes {
			ncs[i].ID = pkg.NodeID("full-" + strconv.Itoa(i))
			ncs[i].Address = pkg.NodeAddress(":" + strconv.Itoa(config.baseAddr+i))
		}
	}

	for i := range ncs {
		for k := range ncs {
			ncs[k].Peers[ncs[i].ID] = ncs[i].Address
		}
	}

	return ncs
}

func setupTest(config TestConfig) (protocol Test) {

	ncs := genNodeConfigs(config)

	protocol.nodes = make([]*node.Node, config.fullNodes+config.lightNodes)
	// Setup all nodes and th grpc: the client connection is closinge corresponding list of nodes for the protocol
	for i, nc := range ncs {
		n := node.NewNode(nc)
		protocol.nodes[i] = n
	}
	protocol.fullNodes = protocol.nodes[:config.fullNodes]
	protocol.lightNodes = protocol.nodes[config.fullNodes:]

	return protocol
}

func TestPeerToPeer(t *testing.T) {
	var testConfig = TestConfig{3, 0, 40000}
	prot := setupTest(testConfig)

	// var fheParams = rlwe.TestPN12QP109
	// var sessParams = node.SessionParameters{
	// 	ID:         "test-session-0",
	// 	RLWEParams: fheParams,
	// 	Nodes:      getIDOfPeers(prot.nodes),
	// }

	helloNodes := make([]*manage.ManageService, len(prot.nodes))
	for i, n := range prot.nodes {
		helloNodes[i] = manage.NewManageService(n)
	}

	// Step 1: all nodes start their server routine
	for _, n := range helloNodes {
		go n.StartListening()
	}

	// Step 2: all node try to establish connections with all their peers
	<-time.After(time.Second / 10) // might be needed for debug purposes, but it seems that the Dial method does several retries already in case where the servers are not listening when the first client tries to connect.
	for _, n := range helloNodes {
		n.Node.Connect()
		n.Connect()
	}

	wg := sync.WaitGroup{}
	for _, n := range helloNodes {
		n := n
		wg.Add(1)
		go func() {
			n.GreetAll()
			n.Greets.Wait()
			wg.Done()
		}()
	}
	wg.Wait()

	for _, n := range helloNodes {
		n.StopListening()
	}

	fmt.Println("Done")

}

func TestCloud(t *testing.T) {
	var testConfig = TestConfig{1, 3, 40000}
	prot := setupTest(testConfig)

	cloud := manage.NewManageService(prot.fullNodes[0])
	clients := make([]*manage.ManageService, len(prot.lightNodes))
	for i := range prot.lightNodes {
		clients[i] = manage.NewManageService(prot.lightNodes[i])
	}
	//var fheParams = rlwe.TestPN12QP109
	// var sessParams = SessionParameters{
	// 	ID:         "test-session-0",
	// 	RLWEParams: fheParams,
	// 	Nodes:      getIDOfPeers(prot.nodes),
	// }

	go cloud.StartListening()

	// Step 2: all node try to establish connections with all their peers
	<-time.After(time.Second / 10) // might be needed for debug purposes, but it seems that the Dial method does several retries already in case where the servers are not listening when the first client tries to connect.
	for _, c := range clients {
		c.Node.Connect()
		c.Connect()
	}

	for _, n := range clients {
		n := n
		go func() {
			n.GreetAll()
			n.Greets.Wait()
		}()
	}

	cloud.Greets.Wait()

	cloud.StopListening()

	fmt.Println("Done")
}

func getIDOfPeers(peers []*node.Node) (peerAddresses []pkg.NodeID) {
	peerAddresses = make([]pkg.NodeID, len(peers))
	for i, peer := range peers {
		peerAddresses[i] = peer.ID()
	}

	return peerAddresses
}
