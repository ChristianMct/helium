package node

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/circuits"
	"github.com/ldsec/helium/pkg/coordinator"
	"github.com/ldsec/helium/pkg/objectstore"
	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/protocols"
	"github.com/ldsec/helium/pkg/services/compute"
	"github.com/ldsec/helium/pkg/services/setup"
	"github.com/ldsec/helium/pkg/transport/centralized"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"golang.org/x/net/context"
	"google.golang.org/grpc/metadata"
)

const (
	WriteStats      = false
	numProtoPerNode = 5
)

type protocolTransport struct {
	outshares, inshares  chan protocols.Share
	getAggregationOutput func(context.Context, protocols.Descriptor) (*protocols.AggregationOutput, error)
}

func (n *protocolTransport) IncomingShares() <-chan protocols.Share {
	return n.inshares
}

func (n *protocolTransport) OutgoingShares() chan<- protocols.Share {
	return n.outshares
}

func (n *protocolTransport) GetAggregationOutput(ctx context.Context, pd protocols.Descriptor) (*protocols.AggregationOutput, error) {
	return n.getAggregationOutput(ctx, pd)
}

type computeTransport struct {
	protocolTransport
	putCiphertext func(ctx context.Context, ct pkg.Ciphertext) error
	getCiphertext func(ctx context.Context, ctID pkg.CiphertextID) (*pkg.Ciphertext, error)
}

func (n *computeTransport) PutCiphertext(ctx context.Context, ct pkg.Ciphertext) error {
	return n.putCiphertext(ctx, ct)
}

func (n *computeTransport) GetCiphertext(ctx context.Context, ctID pkg.CiphertextID) (*pkg.Ciphertext, error) {
	return n.getCiphertext(ctx, ctID)
}

type Node struct {
	addr         pkg.NodeAddress
	id, helperId pkg.NodeID
	nodeList     pkg.NodesList

	//peers    map[pkg.NodeID]*Node

	sessions *pkg.SessionStore
	objectstore.ObjectStore
	// pkBackend compute.PublicKeyBackend

	//transport transport.Transport
	srv              *centralized.HeliumServer
	cli              *centralized.HeliumClient
	outgoingShares   chan protocols.Share
	setupTransport   *protocolTransport
	computeTransport *computeTransport

	// services
	setup   *setup.Service
	compute *compute.Service

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
	SetupConfig       setup.ServiceConfig
	ComputeConfig     compute.ServiceConfig
	ObjectStoreConfig objectstore.Config
	TLSConfig         centralized.TLSConfig
}

// type lightNodeServiceTransport struct {
// 	*centralized.HeliumClient
// 	outgoingShares chan protocols.Share
// }

// // GetAggregationFrom queries the designated node id (typically, the aggregator) for the
// // aggregated share of the designated protocol.
// func (lst *lightNodeServiceTransport) GetAggregationFrom(ctx context.Context, nid pkg.NodeID, pd protocols.Descriptor) (*protocols.AggregationOutput, error) {
// 	return lst.HeliumClient.GetAggregationOutput(ctx, pd)
// }

// // IncomingShares returns the channel over which the transport sends
// // incoming shares.
// func (lst *lightNodeServiceTransport) IncomingShares() <-chan protocols.Share {
// 	panic("light nodes cannot receive shares")
// }

// // OutgoingShares returns the channel over which the caller can write
// // shares for the transport to send.
// func (lst *lightNodeServiceTransport) OutgoingShares() chan<- protocols.Share {
// 	return lst.outgoingShares
// }

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
		node.srv = centralized.NewHeliumServer(node.id, node.addr, node.nodeList, node, node)
		node.srv.RegisterWatcher(node)
	} else {
		node.cli = centralized.NewHeliumClient(node.id, node.helperId, node.nodeList.AddressOf(node.helperId))
	}

	node.outgoingShares = make(chan protocols.Share)
	node.setupTransport = &protocolTransport{
		outshares:            node.outgoingShares,
		inshares:             make(chan protocols.Share),
		getAggregationOutput: node.GetAggregationOutput}
	node.computeTransport = &computeTransport{
		protocolTransport: protocolTransport{
			outshares:            node.outgoingShares,
			inshares:             make(chan protocols.Share),
			getAggregationOutput: node.GetAggregationOutput},
		putCiphertext: node.PutCiphertext,
		getCiphertext: node.GetCiphertext}

	// services
	node.setup, err = setup.NewSetupService(node.id, node, config.SetupConfig, node.setupTransport, node.ObjectStore)
	if err != nil {
		return nil, fmt.Errorf("failed to load the setup service: %w", err)
	}

	node.compute, err = compute.NewComputeService(node.id, node, config.ComputeConfig, node.setup, node.computeTransport)
	if err != nil {
		return nil, fmt.Errorf("failed to load the compute service: %w", err)
	}

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

type protocolCoordinator struct {
	incoming, outgoing chan protocols.Event
}

func (hcp *protocolCoordinator) Incoming() <-chan protocols.Event {
	return hcp.incoming
}

func (hcp *protocolCoordinator) Outgoing() chan<- protocols.Event {
	return hcp.outgoing
}

type coordinatorT struct {
	incoming, outgoing chan coordinator.Event
}

func (hcp *coordinatorT) Incoming() <-chan coordinator.Event {
	return hcp.incoming
}

func (hcp *coordinatorT) Outgoing() chan<- coordinator.Event {
	return hcp.outgoing
}

// func (node *Node) Run(ctx context.Context, app App) (sigs chan circuits.Signature, outs chan compute.CircuitOutput, err error) {
func (node *Node) Run(ctx context.Context, app App, ip compute.InputProvider) (cdescs chan<- circuits.Descriptor, outs <-chan circuits.Output, err error) {

	// recovers the session
	sess, exists := node.GetSessionFromContext(ctx)
	if !exists {
		return nil, nil, fmt.Errorf("session `%s` does not exist", sess.ID)
	}

	// App loading

	// registers the app's circuits and infer the setup description
	err = node.compute.RegisterCircuits(app.Circuits)
	if err != nil {
		return nil, nil, fmt.Errorf("could not register all circuits: %w", err)
	}

	if app.SetupDescription == nil {
		return nil, nil, fmt.Errorf("app must provide a setup description") // TODO: inference of setup description from registered circuits.
	}

	//sigList, sigToReceiverSet := setup.DescriptionToSignatureList(setupDesc)
	sigList, _ := setup.DescriptionToSignatureList(*app.SetupDescription)

	cds := make(chan circuits.Descriptor)
	or := make(chan circuits.Output)

	// runs the setup phase
	if node.IsFullNode() {

		setupCoord := &protocolCoordinator{make(chan protocols.Event), make(chan protocols.Event)}

		downstreamDone := make(chan struct{})
		go func() {
			for ev := range setupCoord.outgoing {
				pev := ev
				node.srv.SendEvent(coordinator.Event{Time: time.Now(), ProtocolEvent: &pev})
			}
			//node.srv.CloseEvents()
			close(downstreamDone)
		}()

		go func() {
			err := node.setup.Run(ctx, setupCoord)
			if err != nil {
				panic(err)
			}
		}()

		// TODO: load and verify state from persistent storage
		for _, sig := range sigList {
			sig := sig
			err := node.setup.RunSignature(ctx, sig)
			if err != nil {
				panic(err)
			}
		}

		node.Logf("all signatures run, closing setup downstream")
		close(setupCoord.incoming)

		<-downstreamDone
		node.Logf("setup done Service done")
		close(node.setupDone)

		computeCoord := &coordinatorT{make(chan coordinator.Event), make(chan coordinator.Event)}

		go func() {
			err := node.compute.Run(ctx, ip, or, computeCoord)
			if err != nil {
				panic(err)
			}
		}()

		downstreamDone = make(chan struct{})
		go func() {
			for ev := range computeCoord.outgoing {
				cev := ev
				node.srv.SendEvent(cev)
			}
			close(downstreamDone)
		}()

		go func() {
			<-node.setupDone
			for cd := range cds {
				node.Logf("new circuit descriptor: %s", cd)
				cev := coordinator.Event{CircuitEvent: &circuits.Event{Status: circuits.Started, Descriptor: cd}}
				computeCoord.incoming <- cev
			}
			node.Logf("user closed circuit discription channel, closing downstream")
			close(computeCoord.incoming)
			<-downstreamDone
			node.Logf("compute service done, closing event channel")
			//close(or) already closed by service
			node.srv.CloseEvents()
		}()

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

		setupCoord := &protocolCoordinator{make(chan protocols.Event), make(chan protocols.Event)}
		go func() {
			err := node.setup.Run(ctx, setupCoord)
			if err != nil {
				panic(err)
			}
		}()

		computeCoord := &coordinatorT{make(chan coordinator.Event), make(chan coordinator.Event)}
		go func() {
			err := node.compute.Run(ctx, ip, or, computeCoord)
			if err != nil {
				panic(err)
			}
		}()

		go func() {
			for ev := range events {
				node.Logf("new coordinator event: %s", ev)
				if ev.IsSetupEvent() {
					pev := *ev.ProtocolEvent
					setupCoord.incoming <- pev
				}
				if ev.IsComputeEvent() {
					cev := ev
					computeCoord.incoming <- cev
				}
			}

			node.Logf("upstream done, closing downstream")
			close(setupCoord.incoming)
			close(computeCoord.incoming)
			close(node.setupDone)
		}()

	}

	return cds, or, nil
}

func (n *Node) PutShare(ctx context.Context, s protocols.Share) error {
	switch {
	case s.Type.IsSetup():
		n.setupTransport.inshares <- s
	case s.Type.IsCompute():
		n.computeTransport.inshares <- s
	default:
		return fmt.Errorf("unknown protocol type")
	}
	return nil
}

func (n *Node) GetAggregationOutput(ctx context.Context, pd protocols.Descriptor) (*protocols.AggregationOutput, error) {
	return n.cli.GetAggregationOutput(ctx, pd)
}

func (n *Node) GetProtocolOutput(ctx context.Context, pd protocols.Descriptor) (*protocols.AggregationOutput, error) {
	return n.setup.GetProtocolOutput(ctx, pd)
}

func (n *Node) PutCiphertext(ctx context.Context, ct pkg.Ciphertext) error {
	if n.id == n.helperId {
		return n.compute.PutCiphertext(ctx, ct)
	}
	return n.cli.PutCiphertext(ctx, ct)
}

func (n *Node) GetCiphertext(ctx context.Context, ctID pkg.CiphertextID) (*pkg.Ciphertext, error) {
	if n.id == n.helperId {
		return n.compute.GetCiphertext(ctx, ctID)
	}
	return n.cli.GetCiphertext(ctx, ctID)
}

// Register is called by the transport when a new peer register itself for the setup.
func (s *Node) Register(peer pkg.NodeID) error {
	return errors.Join(s.setup.Register(peer), s.compute.Register(peer))
}

// Unregister is called by the transport when a peer is unregistered from the setup.
func (s *Node) Unregister(peer pkg.NodeID) error {
	return errors.Join(s.setup.Unregister(peer), s.compute.Unregister(peer))
}

func (node *Node) sendShares(ctx context.Context) {
	for share := range node.outgoingShares {
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
	runCircuit := make(map[circuits.ID]circuits.Signature)
	for ev := range events {

		if ev.IsComputeEvent() {
			cid := ev.CircuitEvent.ID
			switch ev.CircuitEvent.Status {
			case circuits.Started:
				runCircuit[cid] = ev.CircuitEvent.Signature
			case circuits.Executing:
				if _, has := runCircuit[cid]; !has {
					err = fmt.Errorf("inconsisted state, circuit %s execution event before start", cid)
					return
				}
			case circuits.Completed, circuits.Failed:
				if _, has := runCircuit[cid]; !has {
					err = fmt.Errorf("inconsisted state, circuit %s termination event before start", cid)
					return
				}
				delete(runCircuit, cid)
				if ev.CircuitEvent.Status == circuits.Completed {
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

// func getSetupDescription(app App, sess *pkg.Session) (sd setup.Description, err error) {
// 	// creates a setup.Description from the config and provided circuits
// 	if app.SetupDescription != nil {
// 		sd = setup.MergeSetupDescriptions(sd, *app.SetupDescription)
// 	} else {
// 		return setup.Description{}, fmt.Errorf("must provide a setup description") // TODO re enable setup inference
// 	}
// 	// for _, cs := range app.Circuits {
// 	// 	// infer setup description
// 	// 	compSd, err := CircuitToSetupDescription(cs, *sess.Params)
// 	// 	if err != nil {
// 	// 		return setup.Description{}, fmt.Errorf("error while converting circuit to setup description: %w", err)
// 	// 	}
// 	// 	// adds the circuit's required eval keys to the app's setup description
// 	// 	sd = setup.MergeSetupDescriptions(sd, *compSd)
// 	// }
// 	return sd, nil
// }

// // CircuitToSetupDescription converts a CircuitDescription into a setup.Description by
// // extractiong the keys needed for the correct circuit execution.
// func CircuitToSetupDescription(c circuits.Circuit, params bgv.Parameters) (*setup.Description, error) {
// 	sd := setup.Description{}

// 	cDesc := circuits.Descriptor{Signature: circuits.Signature{Name: "dummy"}}

// 	cd, err := circuits.Parse(c, "dummy-cid", params, nil)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// determine session nodes
// 	sessionNodes := make([]pkg.NodeID, 0)
// 	for client := range cd.InputSet {
// 		nopl, err := url.Parse(string(client))
// 		if err != nil {
// 			panic(fmt.Errorf("invalid operand label: %s", client))
// 		}
// 		sessionNodes = append(sessionNodes, pkg.NodeID(nopl.Host))
// 	}
// 	// log.Printf("[Convert] Session nodes are %v\n", sessionNodes)

// 	// determine aggregators
// 	aggregators := make([]pkg.NodeID, 0)
// 	for _, ksSig := range cd.KeySwitchOps {
// 		aggregators = append(aggregators, pkg.NodeID(ksSig.Args["aggregator"]))
// 	}
// 	// log.Printf("[Convert] Aggregators are %v\n", aggregators)

// 	// Collective Public Key
// 	sd.Cpk = sessionNodes

// 	// Relinearization Key
// 	if cd.NeedRlk {
// 		sd.Rlk = aggregators
// 	}

// 	// Rotation Keys
// 	for GaloisEl := range cd.GaloisKeys {
// 		keyField := struct {
// 			GaloisEl  uint64
// 			Receivers []pkg.NodeID
// 		}{GaloisEl, aggregators}
// 		sd.GaloisKeys = append(sd.GaloisKeys, keyField)
// 	}

// 	// Public Keys of output receivers
// 	// for _, ksSig := range cd.KeySwitchOps {
// 	// 	// there is an external receiver
// 	// 	if ksSig.Type == protocols.PCKS {
// 	// 		sender := pkg.NodeID(ksSig.Args["target"])
// 	// 		receivers := append(aggregators, sessionNodes...)
// 	// 		keyField := struct {
// 	// 			Sender    pkg.NodeID
// 	// 			Receivers []pkg.NodeID
// 	// 		}{sender, receivers}
// 	// 		sd.Pk = append(sd.Pk, keyField)
// 	// 	}
// 	// }

// 	return sd, nil
// }

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
	log.Printf("%s | [node] %s\n", node.id, fmt.Sprintf(msg, v...))
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

func (n *Node) GetCollectivePublicKey(ctx context.Context) (*rlwe.PublicKey, error) {
	n.WaitForSetupDone()
	return n.setup.GetCollectivePublicKey(ctx)
}

func (n *Node) GetGaloisKey(ctx context.Context, galEl uint64) (*rlwe.GaloisKey, error) {
	n.WaitForSetupDone()
	return n.setup.GetGaloisKey(ctx, galEl)
}

func (n *Node) GetRelinearizationKey(ctx context.Context) (*rlwe.RelinearizationKey, error) {
	n.WaitForSetupDone()
	return n.setup.GetRelinearizationKey(ctx)
}
