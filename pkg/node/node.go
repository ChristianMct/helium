package node

import (
	"fmt"
	"log"
	"net"
	"time"

	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/ldsec/helium/pkg/utils"

	"github.com/tuneinsight/lattigo/v3/drlwe"
	"github.com/tuneinsight/lattigo/v3/rlwe"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/metadata"
)

const MaxMsgSize = 1024 * 1024 * 20

type Dialer = func(c context.Context, s string) (net.Conn, error)

type Context struct {
	C context.Context
}

func (c Context) SenderID() string {
	md, hasIncomingContext := metadata.FromIncomingContext(c.C)
	if hasIncomingContext && len(md.Get("node_id")) == 1 {
		return md.Get("node_id")[0]
	}
	return ""
}

func (c Context) SessionID() pkg.SessionID {
	md, hasIncomingContext := metadata.FromIncomingContext(c.C)
	if hasIncomingContext && len(md.Get("session_id")) == 1 {
		return pkg.SessionID(md.Get("session_id")[0])
	}
	return ""
}

type Node struct {
	// Self-information
	addr pkg.NodeAddress
	id   pkg.NodeID

	// Protocol information
	peers map[pkg.NodeID]*Node

	conn *grpc.ClientConn

	grpcServer *grpc.Server

	sessions *pkg.SessionStore
}

type NodeConfig struct {
	ID                pkg.NodeID
	Address           pkg.NodeAddress
	Peers             map[pkg.NodeID]pkg.NodeAddress
	SessionParameters []SessionParameters
}

// NewNode initialises a new node according to a given NodeConfig which provides the address and peers of this node
// Also initialises other attributes such as the parameters, session store and the WaitGroup Greets
// also initialises the peers of the node by calling initPeerNode().
func NewNode(config NodeConfig) (node *Node, err error) {
	node = new(Node)

	node.addr = config.Address
	node.id = config.ID
	node.sessions = pkg.NewSessionStore()

	node.peers = make(map[pkg.NodeID]*Node, len(config.Peers))
	for id, peerAddr := range config.Peers {
		if id == node.id {
			return nil, fmt.Errorf("node config should not include node as peer")
		}
		node.peers[id] = newPeerNode(id, peerAddr)
	}

	if node.HasAddress() {
		node.grpcServer = grpc.NewServer(grpc.MaxRecvMsgSize(MaxMsgSize), grpc.MaxSendMsgSize(MaxMsgSize))
		log.Printf("Node %s | started as full helium node at address %s\n", node.id, node.addr)
	} else {
		log.Printf("Node %s | started as light helium node\n", node.id)
	}

	for _, sp := range config.SessionParameters {
		_, err := node.CreateNewSession(sp)
		if err != nil {
			panic(err)
		}
	}

	return node, nil
}

func (n *Node) RegisterService(sd *grpc.ServiceDesc, ss interface{}) {
	n.grpcServer.RegisterService(sd, ss)
}

// Peers returns a map of (NodeID, *Node) containing each peer of Node n.
func (n Node) Peers() map[pkg.NodeID]*Node {
	return n.peers
}

func (n Node) Conns() map[pkg.NodeID]*grpc.ClientConn {
	conns := make(map[pkg.NodeID]*grpc.ClientConn)
	for peerID, peer := range n.peers {
		if peer.conn != nil {
			conns[peerID] = peer.conn
		}
	}
	return conns
}

func (n Node) Dialers() map[pkg.NodeID]Dialer {
	dialers := make(map[pkg.NodeID]Dialer)
	for _, peer := range n.peers {
		if peer.HasAddress() {
			addr := peer.addr
			dialers[peer.id] = func(c context.Context, s string) (net.Conn, error) {
				return net.Dial("tcp", addr.String())
			}
		}
	}
	return dialers
}

func (n Node) ID() pkg.NodeID {
	return n.id
}

func (n Node) HasAddress() bool {
	return n.addr != ""
}

func (n Node) GetPeer(peerId pkg.NodeID) (*Node, error) {
	peer := n.peers[peerId] // not concurrency-safe - not sure if that's a problem
	if peer != nil {
		return peer, nil
	}
	return nil, fmt.Errorf("node %s does not have peer %s", n.id, peerId)
}

func (n Node) HelperPeer() (*Node, error) {
	if n.HasAddress() {
		return nil, fmt.Errorf("full node doesn't have helper peers")
	}

	for _, node := range n.peers {
		if node.HasAddress() {
			return node, nil
		}
	}
	return nil, fmt.Errorf("no helper peer")
}

// newPeerNode initialises a peer node with a given address
func newPeerNode(id pkg.NodeID, addr pkg.NodeAddress) (node *Node) {
	node = new(Node)
	node.id = id
	node.addr = addr
	return node
}

// StartListening starts listening on the tcp port represented by the node address.
// It also initialises a new grpc Server which is registers to the node's corresponding grpc service servers.
// It then accepts incoming connections on the node's network listener.
func (node *Node) StartListening(lis net.Listener) {
	if err := node.grpcServer.Serve(lis); err != nil {
		log.Printf("Node %s | failed to serve: %v\n", node.addr, err)
	}
}

// StopListening stops the tcp connection gracefully. It blocks until all pending grpc requests are handled and
// does not accept new ones.
func (node *Node) StopListening() {
	node.grpcServer.GracefulStop()
	log.Printf("Node %s | has shut down\n", node.id)
}

// Connect creates Clients and Dials for each peer i of the Node n and stores them in node.peer[i].client.
func (node *Node) Connect() (err error) {
	return node.ConnectWithDialers(node.Dialers())
}

// ConnectWithDialers will, given a map m of Dialers, establish a grpc connection to each peer of Node n present
// in m.
func (node *Node) ConnectWithDialers(dialers map[pkg.NodeID]Dialer) (err error) {
	var conns int
	for _, peer := range node.peers {
		dialer, has := dialers[peer.id]
		if peer.id != node.id && has && peer.HasAddress() {
			peer.conn, err = grpc.Dial(string(peer.addr),
				grpc.WithContextDialer(dialer),
				grpc.WithInsecure(),
				grpc.WithBlock(),
				grpc.WithConnectParams(grpc.ConnectParams{Backoff: backoff.DefaultConfig, MinConnectTimeout: 1 * time.Second}),
				grpc.WithDefaultCallOptions(
					grpc.MaxCallRecvMsgSize(MaxMsgSize),
					grpc.MaxCallSendMsgSize(MaxMsgSize)),
			)
			if err != nil {
				return fmt.Errorf("fail to dial: %w", err)
			}
			conns++
		}
	}

	log.Printf("Node %s | is connected to %d peers\n", node.id, conns)
	return nil
}

type SessionParameters struct {
	ID         pkg.SessionID
	RLWEParams rlwe.ParametersLiteral
	T          int
	Nodes      []pkg.NodeID
	ShamirPks  map[pkg.NodeID]drlwe.ShamirPublicPoint
	CRSKey     []byte
}

// CreateNewSession takes an int id and creates a new rlwe session with this node and its peers and a sessionID constructed using the given id.
func (node *Node) CreateNewSession(sessParams SessionParameters) (sess *pkg.Session, err error) {
	// sessionID = "p2p" + node.addr + "." + fmt.Sprint(id)
	// peerAddr := getAddrOfPeers(node.peers)

	fheParams, err := rlwe.NewParametersFromLiteral(sessParams.RLWEParams)
	if err != nil {
		return
	}

	if sessParams.T == 0 {
		sessParams.T = len(sessParams.Nodes)
	}

	var sk *rlwe.SecretKey
	// node generates its secret-key for the session
	if utils.NewSet(sessParams.Nodes).Contains(node.id) {
		kg := rlwe.NewKeyGenerator(fheParams)
		sk = kg.GenSecretKey()
	}

	sess, err = node.sessions.NewRLWESession(&fheParams, sk, sessParams.CRSKey, node.id, sessParams.Nodes, sessParams.T, sessParams.ShamirPks, sessParams.ID)
	if err != nil {
		return sess, err
	}

	log.Printf("Node %s | created rlwe session with id: %s and nodes: %s \n", node.id, sess.ID, sess.Nodes)

	return sess, nil
}

func (node *Node) GetContext(sessionID pkg.SessionID) context.Context {
	md := metadata.Pairs("session_id", string(sessionID), "node_id", string(node.id))
	return metadata.NewOutgoingContext(context.Background(), md)
}

func (node *Node) GetSessionFromID(sessionID pkg.SessionID) (*pkg.Session, bool) {
	return node.sessions.GetSessionFromID(sessionID)
}
