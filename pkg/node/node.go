package node

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/circuits"
	"github.com/ldsec/helium/pkg/objectstore"
	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/services/compute"
	"github.com/ldsec/helium/pkg/services/setup"
	"github.com/ldsec/helium/pkg/transport"
	"github.com/ldsec/helium/pkg/transport/grpctrans"
	"golang.org/x/net/context"
	"google.golang.org/grpc/metadata"
)

const WriteStats = false

type Node struct {
	addr pkg.NodeAddress
	id   pkg.NodeID

	peers    map[pkg.NodeID]*Node
	nodeList pkg.NodesList

	sessions *pkg.SessionStore

	setup   *setup.Service
	compute *compute.Service

	transport transport.Transport

	objectstore.ObjectStore

	pkBackend compute.PublicKeyBackend

	postsetupHandler  func(*pkg.SessionStore, compute.PublicKeyBackend) error
	precomputeHandler func(*pkg.SessionStore, compute.PublicKeyBackend) error

	setupDone chan struct{}
}

type Config struct {
	ID                pkg.NodeID
	Address           pkg.NodeAddress
	SessionParameters []pkg.SessionParameters
	ObjectStoreConfig objectstore.Config
	TLSConfig         grpctrans.TLSConfig
}

// NewNode creates a new Helium node from the provided config and node list.
func NewNode(config Config, nodeList pkg.NodesList) (node *Node, err error) {

	trans, err := grpctrans.NewTransport(config.ID, config.Address, nodeList, config.TLSConfig)
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
	var cloudID pkg.NodeID
	for _, peer := range nodeList {
		if peer.NodeID != node.id {
			node.peers[peer.NodeID] = newPeerNode(peer.NodeID, peer.NodeAddress)
		}
		if len(peer.NodeAddress) > 0 {
			cloudID = peer.NodeID
		}
	}
	node.nodeList = nodeList

	os, err := objectstore.NewObjectStoreFromConfig(config.ObjectStoreConfig)
	if err != nil {
		return nil, err
	}

	for _, sp := range config.SessionParameters {
		_, err = node.CreateNewSession(sp, os)
		if err != nil {
			panic(err)
		}
	}

	node.setup, err = setup.NewSetupService(node.id, cloudID, node, node.transport.GetSetupTransport(), os)
	if err != nil {
		return nil, fmt.Errorf("failed to load the setup service: %w", err)
	}

	node.pkBackend = compute.NewCachedPublicKeyBackend(node.setup)
	node.compute, err = compute.NewComputeService(node.id, cloudID, node, node.transport.GetComputeTransport(), node.pkBackend)
	if err != nil {
		return nil, fmt.Errorf("failed to load the compute service: %w", err)
	}

	node.transport.RegisterSetupService(node.setup)
	node.transport.RegisterComputeService(node.compute)

	node.postsetupHandler = func(sessStore *pkg.SessionStore, pkb compute.PublicKeyBackend) error { return nil }
	node.precomputeHandler = func(sessStore *pkg.SessionStore, pkb compute.PublicKeyBackend) error { return nil }

	node.setupDone = make(chan struct{})

	return node, nil
}

func (node *Node) Run(ctx context.Context, app App) (sigs chan circuits.Signature, outs chan compute.CircuitOutput, err error) {
	sessId, _ := pkg.SessionIDFromContext(ctx)
	sess, exists := node.GetSessionFromID(sessId)
	if !exists {
		return nil, nil, fmt.Errorf("session `%s` was not created", sessId)
	}
	N := len(sess.Nodes)
	T := sess.T

	for cName, circuit := range app.Circuits {
		compute.RegisterCircuit(cName, circuit)
	}

	// creates a setup.Description from the config and provided circuits
	var setupDesc setup.Description
	if app.SetupDescription != nil {
		setupDesc = setup.MergeSetupDescriptions(setupDesc, *app.SetupDescription)
	}
	for _, cs := range app.Circuits {
		// infer setup description
		compSd, err := setup.CircuitToSetupDescription(cs, *sess.Params)
		if err != nil {
			return nil, nil, fmt.Errorf("error while converting circuit to setup description: %w", err)
		}
		// adds the circuit's required eval keys to the app's setup description
		setupDesc = setup.MergeSetupDescriptions(setupDesc, compSd)
	}

	setupSrv, computeSrv := node.GetSetupService(), node.GetComputeService()
	// executes the setup phase
	go func() {
		start := time.Now()
		err = setupSrv.Execute(ctx, setupDesc)
		if err != nil {
			panic(fmt.Errorf("error during setup: %w", err))
		}
		elapsed := time.Since(start)
		node.OutputStats("setup", elapsed, WriteStats, map[string]string{"N": strconv.Itoa(N), "T": strconv.Itoa(T)})
		node.ResetNetworkStats()
		node.postsetupHandler(node.sessions, node.pkBackend)
		close(node.setupDone)
	}()

	sigs = make(chan circuits.Signature)
	outs = make(chan compute.CircuitOutput)

	go func() {
		<-node.setupDone
		if err := node.precomputeHandler(node.sessions, setupSrv); err != nil {
			panic(fmt.Errorf("precomputeHandler returned an error: %w", err))
		}
		start := time.Now()
		err = computeSrv.Execute(ctx, sigs, *app.InputProvider, outs)
		if err != nil {
			panic(fmt.Errorf("error during compute: %w", err)) // TODO return error somehow
		}
		elapsed := time.Since(start)
		node.OutputStats("compute", elapsed, WriteStats, map[string]string{"N": strconv.Itoa(N), "T": strconv.Itoa(T)})

	}()

	return sigs, outs, nil
}

func (node *Node) WaitForSetupDone() {
	<-node.setupDone
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
func (node *Node) CreateNewSession(sessParams pkg.SessionParameters, objstore objectstore.ObjectStore) (sess *pkg.Session, err error) {
	// note: this creates a session with no secret key for nodes outside the session.
	sess, err = node.sessions.NewRLWESession(sessParams, node.id, objstore)
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

// Close releases all the resources allocated by the node.
func (node *Node) Close() error {
	return node.sessions.Close()
}

func (node *Node) Logf(msg string, v ...any) {
	log.Printf("%s | %s\n", node.id, fmt.Sprintf(msg, v...))
}

// outputStats outputs the total network usage and time take to execute a protocol phase.
func (node *Node) OutputStats(phase string, elapsed time.Duration, write bool, metadata ...map[string]string) {
	log.Println("==============", phase, "phase ==============")
	log.Printf("%s | time %s", node.ID(), elapsed)
	log.Printf("%s | network: %s\n", node.ID(), node.GetTransport().GetNetworkStats())
	if write {
		stats := map[string]string{
			"Wall":  fmt.Sprint(elapsed),
			"Sent":  fmt.Sprint(node.GetTransport().GetNetworkStats().DataSent),
			"Recvt": fmt.Sprint(node.GetTransport().GetNetworkStats().DataRecv),
			"ID":    fmt.Sprint(node.ID()),
			"Phase": phase,
		}
		for _, md := range metadata {
			for k, v := range md {
				stats[k] = v
			}
		}
		var statsJSON []byte
		statsJSON, err := json.MarshalIndent(stats, "", "\t")
		if err != nil {
			panic(err)
		}
		if errWrite := os.WriteFile(fmt.Sprintf("/helium/stats/%s-%s.json", phase, node.ID()), statsJSON, 0600); errWrite != nil {
			log.Println(errWrite)
		}
	}
}

func (node *Node) ResetNetworkStats() {
	node.transport.ResetNetworkStats()
}

func (node *Node) RegisterPostsetupHandler(h func(*pkg.SessionStore, compute.PublicKeyBackend) error) {
	node.postsetupHandler = h
}

func (node *Node) RegisterPrecomputeHandler(h func(*pkg.SessionStore, compute.PublicKeyBackend) error) {
	node.precomputeHandler = h
}

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
