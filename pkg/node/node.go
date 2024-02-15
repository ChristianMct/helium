package node

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/circuits"
	"github.com/ldsec/helium/pkg/coordinator"
	"github.com/ldsec/helium/pkg/objectstore"
	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/protocols"
	"github.com/ldsec/helium/pkg/services/setup"
	"github.com/ldsec/helium/pkg/transport/centralized"
	"github.com/ldsec/helium/pkg/utils"
	"golang.org/x/net/context"
	"google.golang.org/grpc/metadata"
)

const (
	WriteStats      = false
	numProtoPerNode = 5
)

type Node struct {
	addr         pkg.NodeAddress
	id, helperId pkg.NodeID
	nodeList     pkg.NodesList

	//peers    map[pkg.NodeID]*Node

	sessions *pkg.SessionStore
	objectstore.ObjectStore
	//pkBackend compute.PublicKeyBackend

	// coordination
	connectedNodes map[pkg.NodeID]utils.Set[pkg.ProtocolID]
	L              sync.RWMutex
	C              sync.Cond

	//transport transport.Transport
	srv                 *centralized.HeliumServer
	cli                 *centralized.HeliumClient
	outshares, inshares chan protocols.Share

	// services
	setup *setup.Service
	//compute *compute.Service

	// postsetupHandler  func(*pkg.SessionStore, compute.PublicKeyBackend) error
	// precomputeHandler func(*pkg.SessionStore, compute.PublicKeyBackend) error

	setupDone   chan struct{}
	computeDone chan struct{}
}

type Config struct {
	ID                pkg.NodeID
	Address           pkg.NodeAddress
	HelperID          pkg.NodeID
	SessionParameters []pkg.SessionParameters
	ObjectStoreConfig objectstore.Config
	TLSConfig         centralized.TLSConfig
}

type lightNodeServiceTransport struct {
	*centralized.HeliumClient
	outgoingShares chan protocols.Share
}

// GetAggregationFrom queries the designated node id (typically, the aggregator) for the
// aggregated share of the designated protocol.
func (lst *lightNodeServiceTransport) GetAggregationFrom(ctx context.Context, nid pkg.NodeID, pd protocols.Descriptor) (*protocols.AggregationOutput, error) {
	return lst.HeliumClient.GetAggregationOutput(ctx, pd)
}

// IncomingShares returns the channel over which the transport sends
// incoming shares.
func (lst *lightNodeServiceTransport) IncomingShares() <-chan protocols.Share {
	panic("light nodes cannot receive shares")
}

// OutgoingShares returns the channel over which the caller can write
// shares for the transport to send.
func (lst *lightNodeServiceTransport) OutgoingShares() chan<- protocols.Share {
	return lst.outgoingShares
}

// NewNode creates a new Helium node from the provided config and node list.
func NewNode(config Config, nodeList pkg.NodesList) (node *Node, err error) {
	node = new(Node)

	if len(config.ID) == 0 {
		return nil, fmt.Errorf("config must specify a node ID")
	}
	if len(config.HelperID) == 0 {
		return nil, fmt.Errorf("config must specify a helper ID")
	}

	node.id = config.ID
	node.addr = config.Address
	node.helperId = config.HelperID
	node.nodeList = nodeList

	// object store
	node.ObjectStore, err = objectstore.NewObjectStoreFromConfig(config.ObjectStoreConfig)
	if err != nil {
		return nil, err
	}

	// session
	node.sessions = pkg.NewSessionStore()
	for _, sp := range config.SessionParameters {
		_, err = node.CreateNewSession(sp, node.ObjectStore)
		if err != nil {
			panic(err)
		}
	}

	// transport
	if node.HasAddress() {
		node.srv = centralized.NewHeliumServer(node.id, node.addr, node.nodeList, node)
		node.srv.RegisterWatcher(node)
	} else {
		node.cli = centralized.NewHeliumClient(node.id, node.helperId, node.nodeList.AddressOf(node.helperId))
	}
	node.inshares = make(chan protocols.Share)
	node.outshares = make(chan protocols.Share)

	// Executor
	executor, err := protocols.NewExectutor(node.id, node, node)
	executor.RunService(context.Background())

	// services
	node.setup, err = setup.NewSetupService(node.id, executor, node.cli, node.ObjectStore)
	if err != nil {
		return nil, fmt.Errorf("failed to load the setup service: %w", err)
	}

	//node.pkBackend = compute.NewCachedPublicKeyBackend(node.setup)
	// node.compute, err = compute.NewComputeService(node.id, node.helperId, node, node.transport.GetComputeTransport(), node.pkBackend)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to load the compute service: %w", err)
	// }

	node.connectedNodes = make(map[pkg.NodeID]utils.Set[pkg.ProtocolID])
	node.C = *sync.NewCond(&node.L)

	// internal
	// node.postsetupHandler = func(sessStore *pkg.SessionStore, pkb compute.PublicKeyBackend) error { return nil }
	// node.precomputeHandler = func(sessStore *pkg.SessionStore, pkb compute.PublicKeyBackend) error { return nil }
	node.setupDone = make(chan struct{})
	node.computeDone = make(chan struct{})

	return node, err
}

// // NewNodeWithTransport creates a new Helium node from the provided config, node list and user-defined transport layer.
// func NewNodeWithTransport(config Config, nodeList pkg.NodesList, trans transport.Transport) (node *Node, err error) {
// 	node = new(Node)

// 	node.addr = config.Address
// 	node.id = config.ID
// 	node.sessions = pkg.NewSessionStore()
// 	node.transport = trans
// 	node.peers = make(map[pkg.NodeID]*Node, len(nodeList))
// 	var cloudID pkg.NodeID
// 	for _, peer := range nodeList {
// 		if peer.NodeID != node.id {
// 			node.peers[peer.NodeID] = newPeerNode(peer.NodeID, peer.NodeAddress)
// 		}
// 		if len(peer.NodeAddress) > 0 {
// 			cloudID = peer.NodeID
// 		}
// 	}
// 	node.nodeList = nodeList

// 	os, err := objectstore.NewObjectStoreFromConfig(config.ObjectStoreConfig)
// 	if err != nil {
// 		return nil, err
// 	}

// 	for _, sp := range config.SessionParameters {
// 		_, err = node.CreateNewSession(sp, os)
// 		if err != nil {
// 			panic(err)
// 		}
// 	}

// 	node.setup, err = setup.NewSetupService(node.id, cloudID, node, node.transport.GetSetupTransport(), os)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to load the setup service: %w", err)
// 	}

// 	node.pkBackend = compute.NewCachedPublicKeyBackend(node.setup)
// 	node.compute, err = compute.NewComputeService(node.id, cloudID, node, node.transport.GetComputeTransport(), node.pkBackend)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to load the compute service: %w", err)
// 	}

// 	node.transport.RegisterSetupService(node.setup)
// 	node.transport.RegisterComputeService(node.compute)

// 	node.postsetupHandler = func(sessStore *pkg.SessionStore, pkb compute.PublicKeyBackend) error { return nil }
// 	node.precomputeHandler = func(sessStore *pkg.SessionStore, pkb compute.PublicKeyBackend) error { return nil }

// 	node.setupDone = make(chan struct{})
// 	node.computeDone = make(chan struct{})

// 	return node, nil
// }

type helperProtocolCoordinator struct {
	outgoing chan protocols.Event
}

func (hcp *helperProtocolCoordinator) Incoming() <-chan protocols.Event {
	return nil
}

func (hcp *helperProtocolCoordinator) Outgoing() chan<- protocols.Event {
	return hcp.outgoing
}

type nodeProtocolCoordinator struct {
	incoming chan protocols.Event
}

func (hcp *nodeProtocolCoordinator) Incoming() <-chan protocols.Event {
	return hcp.incoming
}

func (hcp *nodeProtocolCoordinator) Outgoing() chan<- protocols.Event {
	return nil
}

// func (node *Node) RunNew(ctx context.Context, app App) (sigs chan circuits.Signature, outs chan compute.CircuitOutput, err error) {
func (node *Node) RunNew(ctx context.Context, app App) (sigs chan circuits.Signature, outs chan interface{}, err error) {

	// recovers the session
	sess, exists := node.GetSessionFromContext(ctx)
	if !exists {
		return nil, nil, fmt.Errorf("session `%s` does not exist", sess.ID)
	}

	// registers the app's circuits and infer the setup description
	// for cName, circuit := range app.Circuits {
	// 	compute.RegisterCircuit(cName, circuit)
	// }
	setupDesc, err := getSetupDescription(app, sess)
	if err != nil {
		return nil, nil, err
	}

	//sigList, sigToReceiverSet := setup.DescriptionToSignatureList(setupDesc)
	sigList, _ := setup.DescriptionToSignatureList(setupDesc)

	if node.IsFullNode() {

		coord := &helperProtocolCoordinator{make(chan protocols.Event)}

		go func() {
			for ev := range coord.outgoing {
				pev := ev
				node.srv.SendEvent(coordinator.Event{Time: time.Now(), ProtocolEvent: &pev})
			}
			node.srv.CloseEvents()
		}()

		node.setup.RunService(ctx, coord)

		// TODO: load and verify state from persistent storage
		for _, sig := range sigList {
			sig := sig
			pdc := make(chan protocols.Descriptor)
			go func() {
				pdc <- node.getProtocolDescriptor(sig, sess.T)
			}()
			select {
			case pd := <-pdc:
				err = node.setup.RunProtocol(ctx, pd)
				if err != nil {
					return nil, nil, err
				}
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}

		}

		node.Logf("all signatures run, closing")
		close(coord.outgoing)

	} else {
		events, present, err := node.cli.Register(ctx)
		if err != nil {
			return nil, nil, err
		}

		//completedProto, runningProto, completedCirc, runningCirc, err := recoverPresentState(events, present)
		_, _, _, _, err = recoverPresentState(events, present)
		if err != nil {
			return nil, nil, err
		}

		go node.sendShares(ctx)

		coord := &nodeProtocolCoordinator{incoming: make(chan protocols.Event)}
		node.setup.RunService(ctx, coord)
		for ev := range events {
			if ev.IsSetupEvent() {
				pev := *ev.ProtocolEvent
				coord.incoming <- pev
			}
		}

		node.Logf("helper closed the event log, closing")
	}

	return
}

func (n *Node) PutShare(_ context.Context, s protocols.Share) error {
	n.inshares <- s
	return nil
}

func (n *Node) GetProtocolOutput(ctx context.Context, pd protocols.Descriptor) (*protocols.AggregationOutput, error) {
	return n.setup.GetProtocolOutput(ctx, pd)
}

func (n *Node) IncomingShares() <-chan protocols.Share {
	return n.inshares
}

func (n *Node) OutgoingShares() chan<- protocols.Share {
	return n.outshares
}

// Register is called by the transport when a new peer register itself for the setup.
func (s *Node) Register(peer pkg.NodeID) error {
	s.L.Lock()
	defer s.C.Broadcast()
	defer s.L.Unlock()

	if _, has := s.connectedNodes[peer]; has {
		panic("attempting to register a registered node")
	}

	s.connectedNodes[peer] = make(utils.Set[pkg.ProtocolID])

	s.Logf("[Node] registered peer %v, %d online nodes", peer, len(s.connectedNodes))
	return nil // TODO: Implement
}

// Unregister is called by the transport when a peer is unregistered from the setup.
func (s *Node) Unregister(peer pkg.NodeID) error {

	s.L.Lock()
	_, has := s.connectedNodes[peer]
	if !has {
		panic("unregistering an unregistered node")
	}

	s.setup.DisconnectedNode(peer)

	delete(s.connectedNodes, peer)
	s.L.Unlock()

	s.Logf("[Node] unregistered peer %v, %d online nodes", peer, len(s.connectedNodes))
	return nil // TODO: Implement
}

func (s *Node) getAvailable() utils.Set[pkg.NodeID] {
	available := make(utils.Set[pkg.NodeID])
	for nid, nProtos := range s.connectedNodes {
		if len(nProtos) < numProtoPerNode {
			available.Add(nid)
		}
	}
	return available
}

func (s *Node) getProtocolDescriptor(sig protocols.Signature, threshold int) protocols.Descriptor {
	pd := protocols.Descriptor{Signature: sig, Aggregator: s.helperId}

	s.L.Lock()
	var available utils.Set[pkg.NodeID]
	for available = s.getAvailable(); len(available) < threshold; available = s.getAvailable() {
		s.C.Wait()
	}

	selected := utils.GetRandomSetOfSize(threshold, available)
	pd.Participants = selected.Elements()
	for nid := range selected {
		nodeProto := s.connectedNodes[nid]
		nodeProto.Add(pd.ID())
	}
	s.L.Unlock()

	return pd
}

func (node *Node) sendShares(ctx context.Context) {
	for share := range node.outshares {
		if err := node.cli.PutShare(ctx, share); err != nil {
			node.Logf("error while sending share: %s", err)
		}
	}
}

func recoverPresentState(events <-chan coordinator.Event, present int) (completedProto, runningProto []protocols.Descriptor, completedCirc, runningCirc []circuits.Signature, err error) {

	if present == 0 {
		return
	}

	var current int
	runProto := make(map[pkg.ProtocolID]protocols.Descriptor)
	runCircuit := make(map[pkg.CircuitID]circuits.Signature)
	for ev := range events {

		if ev.IsComputeEvent() {
			cid := ev.CircuitID
			switch ev.CircuitEvent.EventType {
			case coordinator.Started:
				runCircuit[cid] = ev.CircuitEvent.Signature
			case coordinator.Executing:
				if _, has := runCircuit[cid]; !has {
					err = fmt.Errorf("inconsisted state, circuit %s execution event before start", cid)
					return
				}
			case coordinator.Completed, coordinator.Failed:
				if _, has := runCircuit[cid]; !has {
					err = fmt.Errorf("inconsisted state, circuit %s termination event before start", cid)
					return
				}
				delete(runCircuit, cid)
				if ev.CircuitEvent.EventType == coordinator.Completed {
					completedCirc = append(completedCirc, ev.CircuitEvent.Signature)
				}
			}
		}

		if ev.IsProtocolEvent() {
			pid := ev.ProtocolEvent.ID()
			switch ev.ProtocolEvent.EventType {
			case protocols.Started:
				runProto[pid] = ev.ProtocolEvent.Descriptor
			case protocols.Executing:
				if _, has := runProto[pid]; !has {
					err = fmt.Errorf("inconsisted state, protocol %s execution event before start", ev.ProtocolEvent.HID())
					return
				}
			case protocols.Completed, protocols.Failed:
				if _, has := runProto[pid]; !has {
					err = fmt.Errorf("inconsisted state, protocol %s termination event before start", ev.ProtocolEvent.HID())
					return
				}
				delete(runProto, pid)
				if ev.ProtocolEvent.EventType == protocols.Completed {
					completedProto = append(completedProto, ev.ProtocolEvent.Descriptor)
				}
			}
		}

		current++
		if current == present {
			break
		}
	}

	return
}

func getSetupDescription(app App, sess *pkg.Session) (sd setup.Description, err error) {
	// creates a setup.Description from the config and provided circuits
	if app.SetupDescription != nil {
		sd = setup.MergeSetupDescriptions(sd, *app.SetupDescription)
	} else {
		return setup.Description{}, fmt.Errorf("must provide a setup description") // TODO re enable setup inference
	}
	// for _, cs := range app.Circuits {
	// 	// infer setup description
	// 	compSd, err := setup.CircuitToSetupDescription(cs, *sess.Params)
	// 	if err != nil {
	// 		return setup.Description{}, fmt.Errorf("error while converting circuit to setup description: %w", err)
	// 	}
	// 	// adds the circuit's required eval keys to the app's setup description
	// 	sd = setup.MergeSetupDescriptions(sd, compSd)
	// }
	return sd, nil
}

// func (node *Node) Run(ctx context.Context, app App) (sigs chan circuits.Signature, outs chan compute.CircuitOutput, err error) {
// 	sessId, _ := pkg.SessionIDFromContext(ctx)
// 	sess, exists := node.GetSessionFromID(sessId)
// 	if !exists {
// 		return nil, nil, fmt.Errorf("session `%s` was not created", sessId)
// 	}
// 	N := len(sess.Nodes)
// 	T := sess.T

// 	for cName, circuit := range app.Circuits {
// 		compute.RegisterCircuit(cName, circuit)
// 	}

// 	// creates a setup.Description from the config and provided circuits
// 	var setupDesc setup.Description
// 	if app.SetupDescription != nil {
// 		setupDesc = setup.MergeSetupDescriptions(setupDesc, *app.SetupDescription)
// 	}
// 	for _, cs := range app.Circuits {
// 		// infer setup description
// 		compSd, err := setup.CircuitToSetupDescription(cs, *sess.Params)
// 		if err != nil {
// 			return nil, nil, fmt.Errorf("error while converting circuit to setup description: %w", err)
// 		}
// 		// adds the circuit's required eval keys to the app's setup description
// 		setupDesc = setup.MergeSetupDescriptions(setupDesc, compSd)
// 	}

// 	setupSrv, computeSrv := node.GetSetupService(), node.GetComputeService()
// 	// executes the setup phase
// 	go func() {
// 		start := time.Now()
// 		err = setupSrv.Execute(ctx, setupDesc)
// 		if err != nil {
// 			panic(fmt.Errorf("error during setup: %w", err))
// 		}
// 		elapsed := time.Since(start)
// 		node.OutputStats("setup", elapsed, WriteStats, map[string]string{"N": strconv.Itoa(N), "T": strconv.Itoa(T)})
// 		node.ResetNetworkStats()
// 		node.postsetupHandler(node.sessions, node.pkBackend)
// 		close(node.setupDone)
// 	}()

// 	sigs = make(chan circuits.Signature)
// 	outsLocal := make(chan compute.CircuitOutput)

// 	go func() {
// 		<-node.setupDone
// 		if err := node.precomputeHandler(node.sessions, setupSrv); err != nil {
// 			panic(fmt.Errorf("precomputeHandler returned an error: %w", err))
// 		}
// 		err = computeSrv.Execute(ctx, sigs, *app.InputProvider, outsLocal)
// 		if err != nil {
// 			panic(fmt.Errorf("error during compute: %w", err)) // TODO return error somehow
// 		}
// 		close(node.computeDone)
// 	}()

// 	outsUser := make(chan compute.CircuitOutput)
// 	go func() {
// 		<-computeSrv.ComputeStart
// 		start := time.Now()
// 		for out := range outsLocal {
// 			outsUser <- out
// 		}
// 		//<-node.computeDone
// 		elapsed := time.Since(start)
// 		node.OutputStats("compute", elapsed, WriteStats, map[string]string{"N": strconv.Itoa(N), "T": strconv.Itoa(T)})
// 		close(outsUser)
// 	}()

// 	return sigs, outsUser, nil
// }

func (node *Node) WaitForSetupDone() {
	<-node.setupDone
}

func (node *Node) GetSetupService() *setup.Service {
	return node.setup
}

// func (node *Node) GetComputeService() *compute.Service {
// 	return node.compute
// }

func (node *Node) NodeList() pkg.NodesList {
	return node.nodeList // TODO copy
}

func (node *Node) ID() pkg.NodeID {
	return node.id
}

func (node *Node) HasAddress() bool {
	return node.addr != ""
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

// // outputStats outputs the total network usage and time take to execute a protocol phase.
// func (node *Node) OutputStats(phase string, elapsed time.Duration, write bool, metadata ...map[string]string) {
// 	dataSent := node.GetTransport().GetNetworkStats().DataSent
// 	dataRecv := node.GetTransport().GetNetworkStats().DataRecv
// 	fmt.Printf("STATS: phase: %s time: %f sent: %f MB recv: %f MB\n", phase, elapsed.Seconds(), float64(dataSent)/float64(1e6), float64(dataRecv)/float64(1e6))
// 	log.Println("==============", phase, "phase ==============")
// 	log.Printf("%s | time %s", node.ID(), elapsed)
// 	log.Printf("%s | network: %s\n", node.ID(), node.GetTransport().GetNetworkStats())
// 	if write {
// 		stats := map[string]string{
// 			"Wall":  fmt.Sprint(elapsed),
// 			"Sent":  fmt.Sprint(dataSent),
// 			"Recvt": fmt.Sprint(dataRecv),
// 			"ID":    fmt.Sprint(node.ID()),
// 			"Phase": phase,
// 		}
// 		for _, md := range metadata {
// 			for k, v := range md {
// 				stats[k] = v
// 			}
// 		}
// 		var statsJSON []byte
// 		statsJSON, err := json.MarshalIndent(stats, "", "\t")
// 		if err != nil {
// 			panic(err)
// 		}
// 		if errWrite := os.WriteFile(fmt.Sprintf("/helium/stats/%s-%s.json", phase, node.ID()), statsJSON, 0600); errWrite != nil {
// 			log.Println(errWrite)
// 		}
// 	}
// }

// func (node *Node) ResetNetworkStats() {
// 	node.transport.ResetNetworkStats()
// }

// func (node *Node) RegisterPostsetupHandler(h func(*pkg.SessionStore, compute.PublicKeyBackend) error) {
// 	node.postsetupHandler = h
// }

// func (node *Node) RegisterPrecomputeHandler(h func(*pkg.SessionStore, compute.PublicKeyBackend) error) {
// 	node.precomputeHandler = h
// }

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
