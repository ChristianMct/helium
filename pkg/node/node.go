// Package node provides the main entry point for the Helium library.
// It defines the Node type, which implements the parties in the MHE-based
// MPC procotoles.
//
// The current implementation specifically targets the helper-assisted setting,
// in which a single helper node coordinates the execution of the setup and compute
// phases, and serves as an aggregator and circuit evaluator.
package node

import (
	"errors"
	"fmt"
	"log"
	"net"
	"slices"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/circuits"
	"github.com/ldsec/helium/pkg/coordinator"
	"github.com/ldsec/helium/pkg/objectstore"
	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/protocols"
	"github.com/ldsec/helium/pkg/services/compute"
	"github.com/ldsec/helium/pkg/services/setup"
	"github.com/ldsec/helium/pkg/transport/centralized"
	"github.com/tuneinsight/lattigo/v4/bgv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"golang.org/x/net/context"
)

// Node represents a Helium node. It is the main entry point for the Helium library.
// The node is responsible for managing the setup and compute services, and instantiates the transport layer.
//
// Two types of nodes are supported in the current implementation:
//   - the helper node coordinates the execution of the setup and compute phases,
//     and serves a an aggregator and circuit evaluator. The helper node must have an
//     address.
//   - the peer nodes connect to the helper node and provide their protocol shares and
//     encrypted inputs to the compuation. Peer nodes do not need to have an address.
type Node struct {
	addr         pkg.NodeAddress
	id, helperId pkg.NodeID
	nodeList     pkg.NodesList

	// sessions and state
	sessions *pkg.SessionStore
	objectstore.ObjectStore

	// transport
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

	setupDone chan struct{}
}

// NewNode creates a new Helium node from the provided config and node list.
// The method returns an error if the config is invalid or if the node list is empty.
func NewNode(config Config, nodeList pkg.NodesList) (node *Node, err error) {
	node = new(Node)

	if err := ValidateConfig(config, nodeList); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
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
		_, err = node.createNewSession(sp, node.ObjectStore)
		if err != nil {
			return nil, err
		}
	}

	// transport
	if node.IsHelperNode() {
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

	return node, err
}

// Connect connects the node's transport layer to the network.
// If the node has an address, it starts a server at the address.
// If the node does not have an address, it connects to the helper node.
func (n *Node) Connect(ctx context.Context) error {
	if n.HasAddress() {
		listener, err := net.Listen("tcp", string(n.addr))
		if err != nil {
			return err
		}
		n.Logf("starting server at %s", n.addr)
		go func() {
			if err := n.srv.Server.Serve(listener); err != nil {
				log.Fatalf("error in grpc serve: %v", err)
			}
		}()
	} else {
		n.Logf("connecting to %s at %s", n.helperId, n.nodeList.AddressOf(n.helperId))
		err := n.cli.Connect()
		if err != nil {
			return err
		}
	}
	return nil
}

// Run runs the node with the provided app under the given context.
// The method returns channels to send circuit descriptors and receive circuit outputs.
//
// In the current implementation:
//   - the method runs the setup and compute phases sequentially.
//   - only the helper node can issue circuit descriptors.
//   - loading and verification of the state from persistent storage is not implemented.
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

	sigList, _ := setup.DescriptionToSignatureList(*app.SetupDescription)

	cds := make(chan circuits.Descriptor)
	or := make(chan circuits.Output)

	// runs the setup phase
	if node.IsHelperNode() {

		setupCoord := &protocolCoordinator{make(chan protocols.Event), make(chan protocols.Event)}

		downstreamDone := make(chan struct{})
		go func() {
			for ev := range setupCoord.outgoing {
				pev := ev
				node.srv.SendEvent(coordinator.Event{ProtocolEvent: &pev})
			}
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

		// read the past events from the log and establish a list of completed and running protocols and circuits.
		complPd, runPd, complCd, runCd, err := recoverPresentState(events, present)
		if err != nil {
			return nil, nil, err
		}

		// Service initialization
		if err := node.setup.Init(ctx, complPd, runPd); err != nil {
			return nil, nil, fmt.Errorf("error at setup service init: %w", err)
		}

		if err := node.compute.Init(ctx, complCd, runCd, complPd, runPd); err != nil {
			return nil, nil, fmt.Errorf("error at compute service init: %w", err)
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

// Close releases all the resources allocated by the node.
// If the node is the helper node, it stops the server and
// waits for the peers to disconnect.
func (node *Node) Close() error {
	if node.IsHelperNode() {
		node.srv.Server.GracefulStop()
	}
	return node.sessions.Close()
}

// Transport interface implementation

// PutShare is called by the transport upon receiving a new share.
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

// GetAggregationOutput returns the aggregation output for a given protocol descriptor.
// If this node is the helper node, the method retrieves the output from the services.
// If this node is a peer node, the method retrieves the output from the helper node.
func (n *Node) GetAggregationOutput(ctx context.Context, pd protocols.Descriptor) (*protocols.AggregationOutput, error) {
	if n.id == n.helperId {
		switch {
		case pd.Signature.Type.IsSetup():
			return n.setup.GetAggregationOutput(ctx, pd)
		// case pd.Signature.Type.IsCompute():
		// 	return n.compute.GetProtocolOutput(ctx, pd)
		default:
			return nil, fmt.Errorf("unknown protocol type")
		}
	}
	return n.cli.GetAggregationOutput(ctx, pd)
}

// PutCiphertext registers a new ciphertext for the compute service.
// If this node is the helper node, the method registers the ciphertext with the service.
// If this node is a peer node, the method sends the ciphertext to the helper node.
func (n *Node) PutCiphertext(ctx context.Context, ct pkg.Ciphertext) error {
	if n.id == n.helperId {
		return n.compute.PutCiphertext(ctx, ct)
	}
	return n.cli.PutCiphertext(ctx, ct)
}

// GetCiphertext returns a ciphertext from the compute service.
// If this node is the helper node, the method retrieves the ciphertext from the service.
// If this node is a peer node, the method retrieves the ciphertext from the helper node.
func (n *Node) GetCiphertext(ctx context.Context, ctID pkg.CiphertextID) (*pkg.Ciphertext, error) {
	if n.id == n.helperId {
		return n.compute.GetCiphertext(ctx, ctID)
	}
	return n.cli.GetCiphertext(ctx, ctID)
}

// WaitForSetupDone blocks until the setup phase is done.
func (node *Node) WaitForSetupDone() {
	<-node.setupDone
}

// NodeList returns the list of nodes known to the node.
func (node *Node) NodeList() pkg.NodesList {
	return slices.Clone(node.nodeList)
}

// ID returns the node's ID.
func (node *Node) ID() pkg.NodeID {
	return node.id
}

// Address returns true if the node has an address.
func (node *Node) HasAddress() bool {
	return node.addr != ""
}

// IsHelperNode returns true if the node is the helper node.
func (node *Node) IsHelperNode() bool {
	return node.id == node.helperId
}

// SignatureParameters used to bootstrap the signature scheme.
type SignatureParameters struct {
	Type api.SignatureType
}

// SessionProvider interface implementation

// GetSessionFromID returns the session with the given ID.
func (node *Node) GetSessionFromID(sessionID pkg.SessionID) (*pkg.Session, bool) {
	return node.sessions.GetSessionFromID(sessionID)
}

// GetSessionFromContext returns the session by extracting the session id from the
// provided context.
func (node *Node) GetSessionFromContext(ctx context.Context) (*pkg.Session, bool) {
	sessID, has := pkg.SessionIDFromContext(ctx)
	if !has {
		return nil, false
	}
	return node.GetSessionFromID(sessID)
}

// Logf writes a log line with the provided message.
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

// pkg.PublicKeyBackend interface implementation

// GetPublicKey returns the collective public key.
func (n *Node) GetCollectivePublicKey(ctx context.Context) (*rlwe.PublicKey, error) {
	n.WaitForSetupDone()
	return n.setup.GetCollectivePublicKey(ctx)
}

// GetGaliosKeys returns the Galois keys for galois element galEl.
func (n *Node) GetGaloisKey(ctx context.Context, galEl uint64) (*rlwe.GaloisKey, error) {
	n.WaitForSetupDone()
	return n.setup.GetGaloisKey(ctx, galEl)
}

// GetRelinearizationKey returns the relinearization key.
func (n *Node) GetRelinearizationKey(ctx context.Context) (*rlwe.RelinearizationKey, error) {
	n.WaitForSetupDone()
	return n.setup.GetRelinearizationKey(ctx)
}

// Coordinator interface implementation

// Register is called by the transport upon connection of a new peer node.
func (s *Node) Register(peer pkg.NodeID) error {
	return errors.Join(s.setup.Register(peer), s.compute.Register(peer))
}

// Unregister is called by the transport upon disconnection of a peer node.
func (s *Node) Unregister(peer pkg.NodeID) error {
	return errors.Join(s.setup.Unregister(peer), s.compute.Unregister(peer))
}

// FHEProvider interface implementation

// GetEncoder returns a lattigo encoder from the context's session.
func (n *Node) GetEncoder(ctx context.Context) (*bgv.Encoder, error) {
	return n.compute.GetEncoder(ctx)
}

// GetEncryptor returns a lattigo encryptor from the context's session.
// The encryptor is initialized with the collective public key.
func (n *Node) GetEncryptor(ctx context.Context) (*rlwe.Encryptor, error) {
	return n.compute.GetEncryptor(ctx)
}

// GetDecryptor returns a lattigo decryptor from the context's session.
// The decryptor is initialized with the node's secret key.
func (n *Node) GetDecryptor(ctx context.Context) (*rlwe.Decryptor, error) {
	return n.compute.GetDecryptor(ctx)
}

func (node *Node) createNewSession(sessParams pkg.SessionParameters, objstore objectstore.ObjectStore) (sess *pkg.Session, err error) {
	sess, err = node.sessions.NewRLWESession(sessParams, node.id, objstore)
	if err != nil {
		return sess, err
	}

	return sess, nil
}

func (node *Node) sendShares(ctx context.Context) {
	for share := range node.outgoingShares {
		if err := node.cli.PutShare(ctx, share); err != nil {
			node.Logf("error while sending share: %s", err)
		}
	}
}

func recoverPresentState(events <-chan coordinator.Event, present int) (completedProto, runningProto []protocols.Descriptor, completedCirc, runningCirc []circuits.Descriptor, err error) {

	if present == 0 {
		return
	}

	var current int
	runProto := make(map[pkg.ProtocolID]protocols.Descriptor)
	runCircuit := make(map[circuits.ID]circuits.Descriptor)
	for ev := range events {

		if ev.IsComputeEvent() {
			cid := ev.CircuitEvent.ID
			switch ev.CircuitEvent.Status {
			case circuits.Started:
				runCircuit[cid] = ev.CircuitEvent.Descriptor
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
					completedCirc = append(completedCirc, ev.CircuitEvent.Descriptor)
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
