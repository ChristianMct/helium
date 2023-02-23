package node

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/ldsec/helium/pkg/api"
	cryptoUtil "github.com/ldsec/helium/pkg/utils/crypto"
	"google.golang.org/grpc/credentials"

	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v4/drlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const MaxMsgSize = 1024 * 1024 * 32

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
	peers    map[pkg.NodeID]*Node
	nodeList pkg.NodesList

	conn *grpc.ClientConn

	grpcServer *grpc.Server

	sessions *pkg.SessionStore

	statsHandler statsHandler

	sigs     SignatureScheme
	tlsSetup *tlsSetup
}

type SignatureScheme struct {
	Type api.SignatureType
	sk   []byte // as generic as possible
}

type Config struct {
	ID                pkg.NodeID
	Address           pkg.NodeAddress
	Peers             map[pkg.NodeID]pkg.NodeAddress
	SessionParameters []SessionParameters
	//SignatureParameters SignatureParameters
	TLSConfig TLSConfig
	//TLSSetup            TLSSetup
}

// NewNode initialises a new node according to a given NodeConfig which provides the address and peers of this node
// Also initialises other attributes such as the parameters, session store and the WaitGroup Greets
// also initialises the peers of the node by calling initPeerNode().
func NewNode(config Config, nodeList pkg.NodesList) (node *Node, err error) {
	node = new(Node)

	node.addr = config.Address
	node.id = config.ID
	node.sessions = pkg.NewSessionStore()

	node.peers = make(map[pkg.NodeID]*Node, len(nodeList))
	for _, peer := range nodeList {
		if peer.NodeID != node.id {
			node.peers[peer.NodeID] = newPeerNode(peer.NodeID, peer.NodeAddress)
		}
	}
	node.nodeList = nodeList

	node.tlsSetup, err = node.getTLSSetup(config.TLSConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to load crypto material: %w", err)
	}
	if !node.tlsSetup.IsValid() {
		return nil, fmt.Errorf("failed to create node: bad TLSConfig")
	}

	if node.tlsSetup.withInsecureChannels {
		node.sigs = SignatureScheme{
			Type: api.SignatureType_NONE,
		}
	} else {
		node.sigs = SignatureScheme{
			Type: api.SignatureType_ED25519,
			sk:   node.tlsSetup.ownSk.(ed25519.PrivateKey),
		}
	}

	if node.IsFullNode() {

		interceptors := []grpc.UnaryServerInterceptor{
			node.serverSigChecker,
		}

		serverOpts := []grpc.ServerOption{
			grpc.MaxRecvMsgSize(MaxMsgSize),
			grpc.MaxSendMsgSize(MaxMsgSize),
			grpc.StatsHandler(&node.statsHandler),
			grpc.ChainUnaryInterceptor(interceptors...),
		}

		if !node.tlsSetup.withInsecureChannels {
			cert := cryptoUtil.X509ToTLS(node.tlsSetup.ownCert, node.tlsSetup.ownSk.(ed25519.PrivateKey))
			ca := x509.NewCertPool()
			ca.AddCert(node.tlsSetup.caCert)
			tlsConfig := &tls.Config{
				ClientAuth:            tls.RequireAndVerifyClientCert,
				Certificates:          []tls.Certificate{cert},
				ClientCAs:             ca,
				VerifyPeerCertificate: node.VfyPeerCerts,
				VerifyConnection:      node.VfyConn,
				MinVersion:            tls.VersionTLS13,
			}
			serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))
		}

		node.grpcServer = grpc.NewServer(serverOpts...)

		log.Printf("Node %s | started as full helium node at address %s\n", node.id, node.addr)
	} else {
		log.Printf("Node %s | started as light helium node\n", node.id)
	}

	for _, sp := range config.SessionParameters {
		_, err = node.CreateNewSession(sp)
		if err != nil {
			panic(err)
		}
	}

	return node, nil
}

func (node *Node) RegisterService(sd *grpc.ServiceDesc, ss interface{}) {
	node.grpcServer.RegisterService(sd, ss)
}

// Peers returns a map of (NodeID, *Node) containing each peer of Node n.
func (node *Node) Peers() map[pkg.NodeID]*Node {
	return node.peers
}

func (node *Node) NodeList() pkg.NodesList {
	return node.nodeList // TODO copy
}

func (node *Node) Conns() map[pkg.NodeID]*grpc.ClientConn {
	conns := make(map[pkg.NodeID]*grpc.ClientConn)
	for peerID, peer := range node.peers {
		if peer.conn != nil {
			conns[peerID] = peer.conn
		}
	}
	return conns
}

func (node *Node) Dialers() map[pkg.NodeID]Dialer {
	dialers := make(map[pkg.NodeID]Dialer)
	for _, peer := range node.peers {
		if peer.HasAddress() {
			addr := peer.addr
			dialers[peer.id] = func(_ context.Context, _ string) (net.Conn, error) {
				return net.Dial("tcp", addr.String())
			}
		}
	}
	return dialers
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

func (node *Node) GetNetworkStats() NetStats {
	node.statsHandler.mu.Lock()
	defer node.statsHandler.mu.Unlock()
	return node.statsHandler.stats
}

func (node *Node) PrintNetworkStats() {
	node.statsHandler.mu.Lock()
	defer node.statsHandler.mu.Unlock()
	log.Println(node.statsHandler.stats)
}

// newPeerNode initialises a peer node with a given address.
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
			interceptors := []grpc.UnaryClientInterceptor{
				node.clientSigner,
			}

			opts := []grpc.DialOption{
				grpc.WithContextDialer(dialer),
				grpc.WithBlock(),
				grpc.WithConnectParams(grpc.ConnectParams{Backoff: backoff.DefaultConfig, MinConnectTimeout: 1 * time.Second}),
				grpc.WithDefaultCallOptions(
					grpc.MaxCallRecvMsgSize(MaxMsgSize),
					grpc.MaxCallSendMsgSize(MaxMsgSize)),
				grpc.WithStatsHandler(&node.statsHandler),
				grpc.WithChainUnaryInterceptor(interceptors...),
			}

			if !node.tlsSetup.withInsecureChannels {
				ownCert := cryptoUtil.X509ToTLS(node.tlsSetup.ownCert, node.tlsSetup.ownSk.(ed25519.PrivateKey))

				ca := x509.NewCertPool()
				ca.AddCert(node.tlsSetup.caCert)
				tlsConfig := &tls.Config{
					ServerName:            string(peer.id),
					Certificates:          []tls.Certificate{ownCert},
					RootCAs:               ca,
					VerifyPeerCertificate: node.VfyPeerCerts,
					VerifyConnection:      node.VfyConn,
					MinVersion:            tls.VersionTLS13,
				}

				opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
			} else {
				opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
			}

			peer.conn, err = grpc.Dial(string(peer.addr), opts...)
			if err != nil {
				return fmt.Errorf("fail to dial: %w", err)
			}
			conns++
		}
	}

	log.Printf("Node %s | is connected to %d peers\n", node.id, conns)
	return nil
}

func (node *Node) IsFullNode() bool {
	return node.HasAddress()
}

type SessionParameters struct {
	ID         pkg.SessionID
	RLWEParams rlwe.ParametersLiteral
	T          int
	Nodes      []pkg.NodeID
	ShamirPks  map[pkg.NodeID]drlwe.ShamirPublicPoint
	CRSKey     []byte
}

// SignatureParameters used to bootstrap the signature scheme.
type SignatureParameters struct {
	Type api.SignatureType
	sk   []byte // todo: generalize this
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
