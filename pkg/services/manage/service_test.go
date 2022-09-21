package manage

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ldsec/helium/pkg/node"
)

func TestPeerToPeer(t *testing.T) {
	var testConfig = node.LocalTestConfig{FullNodes: 3, LightNodes: 0}
	localtest := node.NewLocalTest(testConfig)

	helloNodes := make([]*ManageService, len(localtest.Nodes))
	for i, n := range localtest.Nodes {
		helloNodes[i] = NewManageService(n)
	}

	localtest.Start()

	// Step 2: all node try to establish connections with all their peers
	<-time.After(time.Second / 10) // might be needed for debug purposes, but it seems that the Dial method does several retries already in case where the servers are not listening when the first client tries to connect.
	for _, n := range helloNodes {
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
	var testConfig = node.LocalTestConfig{HelperNodes: 1, LightNodes: 3}
	localtest := node.NewLocalTest(testConfig)

	cloud := NewManageService(localtest.HelperNodes[0])
	clients := make([]*ManageService, len(localtest.LightNodes))
	for i := range localtest.LightNodes {
		clients[i] = NewManageService(localtest.LightNodes[i])
	}

	localtest.Start()

	// Step 2: all node try to establish connections with all their peers
	<-time.After(time.Second / 10) // might be needed for debug purposes, but it seems that the Dial method does several retries already in case where the servers are not listening when the first client tries to connect.
	for _, c := range clients {
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
