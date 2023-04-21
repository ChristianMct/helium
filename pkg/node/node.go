package node

import (
	"fmt"
	"log"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/services/compute"
	"github.com/ldsec/helium/pkg/services/setup"
	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/ldsec/helium/pkg/transport"
	"github.com/ldsec/helium/pkg/transport/grpctrans"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"golang.org/x/net/context"
	"google.golang.org/grpc/metadata"
)

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
	addr pkg.NodeAddress
	id   pkg.NodeID

	peers    map[pkg.NodeID]*Node
	nodeList pkg.NodesList

	sessions *pkg.SessionStore

	setup   *setup.Service
	compute *compute.Service

	transport transport.Transport
}

type Config struct {
	ID                pkg.NodeID
	Address           pkg.NodeAddress
	Peers             map[pkg.NodeID]pkg.NodeAddress
	SessionParameters []pkg.SessionParameters
	TLSConfig         grpctrans.TLSConfig
}

// NewNode creates a new Helium node from the provided config and node list.
func NewNode(config Config, nodeList pkg.NodesList) (node *Node, err error) {

	trans, err := grpctrans.NewTransport(config.ID, nodeList, config.TLSConfig)
	if err != nil {
		return nil, err
	}
	return NewNodeWithTransport(config, nodeList, trans)
}

// NewNodeWithTransport creates a new Helium node from the provided config, node list and user-defined transport layer.
func NewNodeWithTransport(config Config, nodeList pkg.NodesList, trans transport.Transport) (node *Node, err error) {
	node = new(Node)

	node.addr = config.Address
	node.id = config.ID
	node.sessions = pkg.NewSessionStore()
	node.transport = trans
	node.peers = make(map[pkg.NodeID]*Node, len(nodeList))
	for _, peer := range nodeList {
		if peer.NodeID != node.id {
			node.peers[peer.NodeID] = newPeerNode(peer.NodeID, peer.NodeAddress)
		}
	}
	node.nodeList = nodeList

	for _, sp := range config.SessionParameters {
		_, err = node.CreateNewSession(sp)
		if err != nil {
			panic(err)
		}
	}

	node.setup, err = setup.NewSetupService(node.id, node, node.transport.GetSetupTransport())
	if err != nil {
		return nil, fmt.Errorf("failed to load the setup service: %w", err)
	}
	node.compute, err = compute.NewComputeService(node.id, node, node.transport.GetComputeTransport())
	if err != nil {
		return nil, fmt.Errorf("failed to load the compute service: %w", err)
	}

	node.transport.RegisterSetupService(node.setup)
	node.transport.RegisterComputeService(node.compute)

	return node, nil
}

func (node *Node) GetTransport() transport.Transport {
	return node.transport
}

func (node *Node) GetSetupService() *setup.Service {
	return node.setup
}

func (node *Node) GetComputeService() *compute.Service {
	return node.compute
}

func (node *Node) Connect() error {
	return node.transport.Connect()
}

// Peers returns a map of (NodeID, *Node) containing each peer of Node n.
func (node *Node) Peers() map[pkg.NodeID]*Node {
	return node.peers
}

func (node *Node) NodeList() pkg.NodesList {
	return node.nodeList // TODO copy
}

func (node *Node) ID() pkg.NodeID {
	return node.id
}

func (node *Node) HasAddress() bool {
	return node.addr != ""
}

func (node *Node) GetPeer(peerID pkg.NodeID) (*Node, error) {
	peer := node.peers[peerID] // not concurrency-safe - not sure if that's a problem
	if peer != nil {
		return peer, nil
	}
	return nil, fmt.Errorf("peer not found: %s", peerID)
}

func (node *Node) HelperPeer() (*Node, error) {
	if node.HasAddress() {
		return nil, fmt.Errorf("full node doesn't have helper peers")
	}

	for _, node := range node.peers {
		if node.HasAddress() {
			return node, nil
		}
	}
	return nil, fmt.Errorf("no helper peer")
}

// newPeerNode initialises a peer node with a given address.
func newPeerNode(id pkg.NodeID, addr pkg.NodeAddress) (node *Node) {
	node = new(Node)
	node.id = id
	node.addr = addr
	return node
}

func (node *Node) IsFullNode() bool {
	return node.HasAddress()
}

// SignatureParameters used to bootstrap the signature scheme.
type SignatureParameters struct {
	Type api.SignatureType
}

// CreateNewSession takes an int id and creates a new rlwe session with this node and its peers and a sessionID constructed using the given id.
func (node *Node) CreateNewSession(sessParams pkg.SessionParameters) (sess *pkg.Session, err error) {
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

	sess, err = node.sessions.NewRLWESession(&sessParams, &fheParams, sk, sessParams.CRSKey, node.id, sessParams.Nodes, sessParams.T, sessParams.ShamirPks, sessParams.ID)
	if err != nil {
		return sess, err
	}

	log.Printf("Node %s | created rlwe session with id: %s and nodes: %s \n", node.id, sess.ID, sess.Nodes)

	return sess, nil
}

func (node *Node) GetOutgoingContext(sessionID pkg.SessionID) context.Context {
	md := metadata.Pairs("session_id", string(sessionID), "node_id", string(node.id))
	return metadata.NewOutgoingContext(context.Background(), md)
}

func (node *Node) GetSessionFromID(sessionID pkg.SessionID) (*pkg.Session, bool) {
	return node.sessions.GetSessionFromID(sessionID)
}

func (node *Node) GetSessionFromContext(ctx context.Context) (*pkg.Session, bool) {
	sessID, has := pkg.SessionIDFromContext(ctx)
	if !has {
		return nil, false
	}
	return node.GetSessionFromID(sessID)
}

func (node *Node) GetSessionFromIncomingContext(ctx context.Context) (*pkg.Session, bool) {
	sessID := pkg.SessionIDFromIncomingContext(ctx)
	return node.GetSessionFromID(sessID)
}
