package manage

import (
	"sync"
	"testing"
	"time"

	"github.com/ldsec/helium/pkg/node"
)

func TestPeerToPeer(t *testing.T) {
	var testConfig = node.LocalTestConfig{FullNodes: 3, LightNodes: 0}
	localtest := node.NewLocalTest(testConfig)

	helloNodes := make([]*Service, len(localtest.Nodes))
	for i, n := range localtest.Nodes {
		helloNodes[i] = NewManageService(n)
	}

	localtest.Start()

	// Step 2: all node try to establish connections with all their peers
	<-time.After(time.Second / 10) // might be needed for debug purposes, but it seems that the Dial method does several retries already in case where the servers are not listening when the first client tries to connect.
	for _, n := range helloNodes {
		err := n.Connect()
		if err != nil {
			t.Error(err)
		}
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

}

func TestCloud(t *testing.T) {
	var testConfig = node.LocalTestConfig{HelperNodes: 1, LightNodes: 3}
	localtest := node.NewLocalTest(testConfig)

	cloud := NewManageService(localtest.HelperNodes[0])
	clients := make([]*Service, len(localtest.LightNodes))
	for i := range localtest.LightNodes {
		clients[i] = NewManageService(localtest.LightNodes[i])
	}

	localtest.Start()

	// Step 2: all node try to establish connections with all their peers
	<-time.After(time.Second / 10) // might be needed for debug purposes, but it seems that the Dial method does several retries already in case where the servers are not listening when the first client tries to connect.
	for _, c := range clients {
		err := c.Connect()
		if err != nil {
			t.Error(err)
		}
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

}
