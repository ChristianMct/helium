package node

import (
	"fmt"
	pkg "lattigo-cloud/pkg/session"
	"lattigo-cloud/pkg/utils"
	"log"
	"net"
	"time"

	"github.com/tuneinsight/lattigo/v3/drlwe"
	"github.com/tuneinsight/lattigo/v3/rlwe"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/metadata"
)

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
	ShamirPublicKey   drlwe.ShamirPublicPoint
	Peers             map[pkg.NodeID]pkg.NodeAddress
	SessionParameters *SessionParameters
}

// NewNode initialises a new node according to a given NodeConfig which provides the address and peers of this node
// Also initialises other attributes such as the parameters, session store and the WaitGroup Greets
// also initialises the peers of the node by calling initPeerNode()
func NewNode(config NodeConfig) (node *Node) {
	node = new(Node)

	node.addr = config.Address
	node.id = config.ID
	node.sessions = pkg.NewSessionStore()

	if _, isSelfInPeers := config.Peers[node.id]; !isSelfInPeers {
		config.Peers[node.id] = node.addr
	}

	node.peers = make(map[pkg.NodeID]*Node, len(config.Peers))
	for id, peerAddr := range config.Peers {
		node.peers[id] = newPeerNode(id, peerAddr)
	}

	if node.HasAddress() {
		node.grpcServer = grpc.NewServer()
		log.Printf("Node %s | started as full node at address %s\n", node.id, node.addr)
	} else {
		log.Printf("Node %s | started as light node\n", node.id)
	}

	if config.SessionParameters != nil {
		_, err := node.CreateNewSession(*config.SessionParameters)
		if err != nil {
			panic(err)
		}
	}

	return node
}

func (n *Node) RegisterService(sd *grpc.ServiceDesc, ss interface{}) {
	n.grpcServer.RegisterService(sd, ss)
}

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

// newPeerNode initialises a peer node with a given address
func newPeerNode(id pkg.NodeID, addr pkg.NodeAddress) (node *Node) {
	node = new(Node)
	node.id = id
	node.addr = addr
	return node
}

// StartListening starts listening on the tcp port represented by the node address. It also initialises a new grpc Server which is registers to the node's corresponding grpc service servers. It then accepts incoming connections on the node's network listener.
func (node *Node) StartListening() {
	lis, err := net.Listen("tcp", node.addr.String())
	if err != nil {
		log.Printf("Node %s | failed to listen: %v\n", node.addr, err)
	}
	if err := node.grpcServer.Serve(lis); err != nil {
		log.Printf("Node %s | failed to serve: %v\n", node.addr, err)
	}

}

func (node *Node) StopListening() {
	node.grpcServer.GracefulStop()
	log.Printf("Node %s | has shut down\n", node.id)
}

// Connect creates Clients and Dials for each peer i of the Node n and stores them in node.peer[i].client
func (node *Node) Connect() (err error) {
	return node.ConnectWithDialers(node.Dialers())
}

func (node *Node) ConnectWithDialers(dialers map[pkg.NodeID]Dialer) (err error) {
	var conns int
	for peerId, peer := range node.peers {
		dialer, has := dialers[peer.id]
		if peerId != node.id && has {
			peer.conn, err = grpc.Dial(string(peer.addr), grpc.WithContextDialer(dialer), grpc.WithInsecure(), grpc.WithBlock(), grpc.WithConnectParams(grpc.ConnectParams{Backoff: backoff.DefaultConfig, MinConnectTimeout: 20 * time.Second}))
			if err != nil {
				return fmt.Errorf("fail to dial: %v", err)
			}
			conns++
		}
	}

	log.Printf("Node %s | is connected to %d peers\n", node.id, conns)
	return nil
}

type SessionParameters struct {
	ID         string
	RLWEParams rlwe.ParametersLiteral
	T          int
	Nodes      []pkg.NodeID
	ShamirPks  map[pkg.NodeID]drlwe.ShamirPublicPoint
	CRSKey     []byte
}

// CreateNewSession takes an int id and creates a new rlwe session with this node and its peers and a sessionID constructed using the given id.
func (node *Node) CreateNewSession(sessParams SessionParameters) (sess *pkg.Session, err error) {
	//sessionID = "p2p" + node.addr + "." + fmt.Sprint(id)
	//peerAddr := getAddrOfPeers(node.peers)

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

func getAddrOfPeers(peers []*Node) (peerAddresses []string) {
	peerAddresses = make([]string, len(peers))
	for i, peer := range peers {
		peerAddresses[i] = peer.addr.String()
	}

	return peerAddresses
}
