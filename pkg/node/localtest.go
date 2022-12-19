package node

import (
	"log"
	"net"
	"strconv"
	"sync"

	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/tuneinsight/lattigo/v4/drlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"golang.org/x/net/context"
	"google.golang.org/grpc/test/bufconn"
)

const buffConBufferSize = 65 * 1024 * 1024

// LocalTestConfig is a configuration structure for LocalTest types. It is used to
// specify the number of full, light and helper nodes in the local test.
type LocalTestConfig struct {
	FullNodes   int // Number of full nodes in the session
	LightNodes  int // Number of light nodes in the session
	HelperNodes int // number of helper nodes (full nodes that are not in the session key)
	Session     *SessionParameters
}

// LocalTest represent a local test setting with several nodes and a single
// session with group secret key.
type LocalTest struct {
	Nodes       []*Node
	FullNodes   []*Node
	LightNodes  []*Node
	HelperNodes []*Node

	Params      rlwe.Parameters
	SkIdeal     *rlwe.SecretKey
	NodeConfigs []Config
	NodesList
}

// NewLocalTest creates a new LocalTest from the configuration and returns it.
func NewLocalTest(config LocalTestConfig) (test *LocalTest) {

	test = new(LocalTest)
	test.NodeConfigs, test.NodesList = genNodeConfigs(config)
	test.Nodes = make([]*Node, config.FullNodes+config.LightNodes+config.HelperNodes)
	for i, nc := range test.NodeConfigs {
		var err error
		test.Nodes[i], err = NewNode(nc, test.NodesList)
		if err != nil {
			panic(err)
		}
	}
	test.FullNodes = test.Nodes[:config.FullNodes]
	test.LightNodes = test.Nodes[config.FullNodes : config.FullNodes+config.LightNodes]
	test.HelperNodes = test.Nodes[config.FullNodes+config.LightNodes:]

	// initialize the session-related fields if session parameters are given
	if config.Session != nil {
		var err error
		test.Params, err = rlwe.NewParametersFromLiteral(config.Session.RLWEParams)
		if err != nil {
			panic(err)
		}

		test.SkIdeal = rlwe.NewSecretKey(test.Params)
		for _, n := range test.SessionNodes() {
			// computes the ideal secret-key for the test
			sess, _ := n.GetSessionFromID("test-session")
			ski := sess.GetSecretKey()
			test.Params.RingQP().AddLvl(test.SkIdeal.Value.Q.Level(), test.SkIdeal.Value.P.Level(), ski.Value, test.SkIdeal.Value, test.SkIdeal.Value)
		}
	}

	return test
}

// genNodeConfigs generates the necessary NodeConfig for each party specified in the LocalTestConfig.
func genNodeConfigs(config LocalTestConfig) ([]Config, NodesList) {

	ncs := make([]Config, 0, config.FullNodes+config.HelperNodes+config.LightNodes)
	nl := NodesList{}

	sessionNodesIds := make([]pkg.NodeID, 0, config.FullNodes+config.LightNodes)
	nodeShamirPks := make(map[pkg.NodeID]drlwe.ShamirPublicPoint)

	shamirPk := 1
	for i := 0; i < config.FullNodes; i++ {
		nc := Config{ID: pkg.NodeID("full-" + strconv.Itoa(i)), Address: pkg.NodeAddress("local")}
		ncs = append(ncs, nc)
		nl = append(nl, struct {
			pkg.NodeID
			pkg.NodeAddress
		}{nc.ID, nc.Address})
		sessionNodesIds = append(sessionNodesIds, nc.ID)

		nodeShamirPks[nc.ID] = drlwe.ShamirPublicPoint(shamirPk)
		shamirPk++
	}

	for i := 0; i < config.LightNodes; i++ {
		nc := Config{ID: pkg.NodeID("light-" + strconv.Itoa(i))}
		ncs = append(ncs, nc)
		nl = append(nl, struct {
			pkg.NodeID
			pkg.NodeAddress
		}{nc.ID, nc.Address})
		sessionNodesIds = append(sessionNodesIds, nc.ID)

		nodeShamirPks[nc.ID] = drlwe.ShamirPublicPoint(shamirPk)
		shamirPk++
	}

	for i := 0; i < config.HelperNodes; i++ {
		nc := Config{ID: pkg.NodeID("helper-" + strconv.Itoa(i)), Address: pkg.NodeAddress("local")}
		ncs = append(ncs, nc)
		nl = append(nl, struct {
			pkg.NodeID
			pkg.NodeAddress
		}{nc.ID, nc.Address})
	}

	// sets session-specific variables with test values
	if config.Session != nil {
		config.Session.ID = "test-session" // forces the session id
		config.Session.Nodes = sessionNodesIds
		config.Session.CRSKey = []byte{'l', 'a', 't', 't', 'i', 'g', '0'}

		for i := range ncs {
			ncs[i].SessionParameters = []SessionParameters{*config.Session}
			ncs[i].SessionParameters[0].ShamirPks = nodeShamirPks // forces the Shamir pts
		}
	}

	return ncs, nl
}

// Start creates some in-memory connections between the nodes and returns
// when all nodes are connected.
func (lc LocalTest) Start() {
	ds := make(map[pkg.NodeID]Dialer)
	for _, node := range lc.Nodes {
		node := node
		if node.IsFullNode() {
			lis := bufconn.Listen(buffConBufferSize)
			go func() {
				if err := node.grpcServer.Serve(lis); err != nil {
					log.Fatalf("failed to serve: %v", err)
				}
			}()
			ds[node.id] = func(context.Context, string) (net.Conn, error) { return lis.Dial() }
		}
	}

	var wg sync.WaitGroup
	for _, node := range lc.Nodes {
		node := node
		wg.Add(1)
		go func() {
			err := node.ConnectWithDialers(ds)
			if err != nil {
				log.Printf("node %s failed to connect: %v", node.ID(), err)
				return
			}
			wg.Done()
		}()
	}
	wg.Wait()
}

// SessionNodes returns the set of nodes in the local test that are part of the
// session.
func (lc LocalTest) SessionNodes() []*Node {
	return lc.Nodes[:len(lc.FullNodes)+len(lc.LightNodes)]
}

// NodeIds returns the node ideas of all nodes in the local test.
func (lc LocalTest) NodeIds() []pkg.NodeID {
	ids := make([]pkg.NodeID, len(lc.Nodes))
	for i, node := range lc.Nodes {
		ids[i] = node.id
	}
	return ids
}
