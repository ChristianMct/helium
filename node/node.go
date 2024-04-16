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
	"slices"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/circuit"
	"github.com/ChristianMct/helium/objectstore"
	"github.com/ChristianMct/helium/protocol"
	"github.com/ChristianMct/helium/services/compute"
	"github.com/ChristianMct/helium/services/setup"
	"github.com/ChristianMct/helium/session"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
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
	addr         helium.NodeAddress
	id, helperID helium.NodeID
	nodeList     helium.NodesList

	// sessions and state
	sessions *session.SessionStore
	objectstore.ObjectStore

	upstream Coordinator

	// transport
	transport Transport

	// services
	setup   *setup.Service
	compute *compute.Service

	// postsetupHandler  func(*pkg.SessionStore, compute.PublicKeyBackend) error
	// precomputeHandler func(*pkg.SessionStore, compute.PublicKeyBackend) error

	setupDone chan struct{}
}

// New creates a new Helium node from the provided config and node list.
// The method returns an error if the config is invalid or if the node list is empty.
func New(config Config, nodeList helium.NodesList) (node *Node, err error) {
	node = new(Node)

	if err := ValidateConfig(config, nodeList); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	node.id = config.ID
	node.addr = config.Address
	node.helperID = config.HelperID
	node.nodeList = nodeList

	// object store
	node.ObjectStore, err = objectstore.NewObjectStoreFromConfig(config.ObjectStoreConfig)
	if err != nil {
		return nil, err
	}

	// session
	node.sessions = session.NewSessionStore()
	for _, sp := range config.SessionParameters {
		_, err = node.createNewSession(sp)
		if err != nil {
			return nil, err
		}
	}

	// services
	node.setup, err = setup.NewSetupService(node.id, node, config.SetupConfig, node.ObjectStore)
	if err != nil {
		return nil, fmt.Errorf("failed to load the setup service: %w", err)
	}

	node.compute, err = compute.NewComputeService(node.id, node, config.ComputeConfig, node.setup)
	if err != nil {
		return nil, fmt.Errorf("failed to load the compute service: %w", err)
	}

	// internal
	// node.postsetupHandler = func(sessStore *pkg.SessionStore, pkb compute.PublicKeyBackend) error { return nil }
	// node.precomputeHandler = func(sessStore *pkg.SessionStore, pkb compute.PublicKeyBackend) error { return nil }
	node.setupDone = make(chan struct{})

	return node, err
}

// RunNew creates a new Helium node from the provided config and node list, and runs the node with the provided app under the given context.
func RunNew(ctx context.Context, config Config, nodeList helium.NodesList, app App, ip compute.InputProvider, upstream Coordinator, trans Transport) (node *Node, cdescs chan<- circuit.Descriptor, outs <-chan circuit.Output, err error) {
	node, err = New(config, nodeList)
	if err != nil {
		return nil, nil, nil, err
	}

	// err = node.Connect(ctx)
	// if err != nil {
	// 	return nil, nil, nil, err
	// }

	cdescs, outs, err = node.Run(ctx, app, ip, upstream, trans)
	return
}

// Connect connects the node's transport layer to the network.
// If the node has an address, it starts a server at the address.
// If the node does not have an address, it connects to the helper node.
// func (node *Node) Connect(ctx context.Context) error {
// 	if node.HasAddress() {
// 		listener, err := net.Listen("tcp", string(node.addr))
// 		if err != nil {
// 			return err
// 		}
// 		node.Logf("starting server at %s", node.addr)
// 		go func() {
// 			if err := node.srv.Server.Serve(listener); err != nil {
// 				log.Fatalf("error in grpc serve: %v", err)
// 			}
// 		}()
// 	} else {
// 		node.Logf("connecting to %s at %s", node.helperID, node.nodeList.AddressOf(node.helperID))
// 		err := node.cli.Connect()
// 		if err != nil {
// 			return err
// 		}
// 	}
// 	return nil
// }

// Run runs the node with the provided app under the given context.
// The method returns channels to send circuit descriptors and receive circuit outputs.
//
// In the current implementation:
//   - the method runs the setup and compute phases sequentially.
//   - only the helper node can issue circuit descriptors.
//   - loading and verification of the state from persistent storage is not implemented.
func (node *Node) Run(ctx context.Context, app App, ip compute.InputProvider, upstream Coordinator, trans Transport) (cdescs chan<- circuit.Descriptor, outs <-chan circuit.Output, err error) {

	node.upstream = upstream
	node.transport = trans

	// recovers the session
	sess, exists := node.GetSessionFromContext(ctx)
	if !exists {
		return nil, nil, fmt.Errorf("session `%s` does not exist", sess.ID)
	}

	ctx = helium.ContextWithNodeID(ctx, node.id)

	// App loading

	// registers the app's circuits and infer the setup description
	err = node.compute.RegisterCircuits(app.Circuits)
	if err != nil {
		return nil, nil, fmt.Errorf("could not register all circuits: %w", err)
	}

	if app.SetupDescription == nil {
		return nil, nil, fmt.Errorf("app must provide a setup description") // TODO: inference of setup description from registered circuits.
	}

	sigList := setup.DescriptionToSignatureList(*app.SetupDescription)

	cds := make(chan circuit.Descriptor)
	or := make(chan circuit.Output)

	sc, err := newServicesCoordinator(ctx, node.upstream)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating a service coordinator: %w", err)
	}

	st := newServicesTransport(trans)

	// go node.sendShares(ctx)

	go func() {
		err := node.setup.Run(ctx, sc.setupCoordinator, &st.setupTransport)
		if err != nil {
			panic(err)
		}
		close(node.setupDone)
	}()

	// runs the setup phase
	if node.IsHelperNode() {
		// TODO: load and verify state from persistent storage
		for _, sig := range sigList {
			sig := sig
			err := node.setup.RunSignature(ctx, sig)
			if err != nil {
				panic(err)
			}
		}

		node.Logf("all signatures run, closing setup downstream")
		close(sc.setupCoordinator.incoming)
	}

	<-node.setupDone

	node.Logf("setup done, starting compute phase")

	// go func() {
	// 	err := node.compute.Run(ctx, ip, or, sc.computeCoordinator, &st.computeTransport)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// }()

	// if node.IsHelperNode() {
	// 	for cd := range cds {
	// 		node.Logf("new circuit descriptor: %s", cd)
	// 		cev := compute.Event{CircuitEvent: &circuit.Event{EventType: circuit.Started, Descriptor: cd}}
	// 		sc.computeCoordinator.incoming <- cev
	// 	}
	// 	node.Logf("user closed circuit discription channel, closing downstream")
	// 	close(sc.computeCoordinator.incoming)
	// }

	close(or)

	return cds, or, nil
}

// Close releases all the resources allocated by the node.
// If the node is the helper node, it stops the server and
// waits for the peers to disconnect.
// func (node *Node) Close() error {
// 	if node.IsHelperNode() {
// 		node.srv.Server.GracefulStop()
// 	}
// 	return nil
// }

// Transport interface implementation

// GetAggregationOutput returns the aggregation output for a given protocol descriptor.
// If this node is the helper node, the method retrieves the output from the services.
// If this node is a peer node, the method retrieves the output from the helper node.
func (node *Node) GetAggregationOutput(ctx context.Context, pd protocol.Descriptor) (*protocol.AggregationOutput, error) {
	if node.id == node.helperID {
		switch {
		case pd.Signature.Type.IsSetup():
			return node.setup.GetAggregationOutput(ctx, pd)
		default:
			return nil, fmt.Errorf("unknown protocol type")
		}
	}
	return nil, fmt.Errorf("get aggregation output not implemented for ligh nodes")
}

// PutCiphertext registers a new ciphertext for the compute service.
// If this node is the helper node, the method registers the ciphertext with the service.
// If this node is a peer node, the method sends the ciphertext to the helper node.
func (node *Node) PutCiphertext(ctx context.Context, ct helium.Ciphertext) error {
	if node.id == node.helperID {
		return node.compute.PutCiphertext(ctx, ct)
	}
	return fmt.Errorf("put ciphertext not implemented for ligh nodes")
}

// GetCiphertext returns a ciphertext from the compute service.
// If this node is the helper node, the method retrieves the ciphertext from the service.
// If this node is a peer node, the method retrieves the ciphertext from the helper node.
func (node *Node) GetCiphertext(ctx context.Context, ctID helium.CiphertextID) (*helium.Ciphertext, error) {
	if node.id == node.helperID {
		return node.compute.GetCiphertext(ctx, ctID)
	}
	return nil, fmt.Errorf("get ciphertext not implemented for ligh nodes")
}

// WaitForSetupDone blocks until the setup phase is done.
func (node *Node) WaitForSetupDone(ctx context.Context) error {
	select {
	case <-node.setupDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// NodeList returns the list of nodes known to the node.
func (node *Node) NodeList() helium.NodesList {
	return slices.Clone(node.nodeList)
}

// ID returns the node's ID.
func (node *Node) ID() helium.NodeID {
	return node.id
}

// Address returns the node's address.
func (node *Node) Address() helium.NodeAddress {
	return node.addr
}

// HasAddress returns true if the node has an address.
func (node *Node) HasAddress() bool {
	return node.addr != ""
}

// IsHelperNode returns true if the node is the helper node.
func (node *Node) IsHelperNode() bool {
	return node.id == node.helperID
}

// SessionProvider interface implementation

// GetSessionFromID returns the session with the given ID.
func (node *Node) GetSessionFromID(sessionID helium.SessionID) (*session.Session, bool) {
	return node.sessions.GetSessionFromID(sessionID)
}

// GetSessionFromContext returns the session by extracting the session id from the
// provided context.
func (node *Node) GetSessionFromContext(ctx context.Context) (*session.Session, bool) {
	sessID, has := helium.SessionIDFromContext(ctx)
	if !has {
		return nil, false
	}
	return node.GetSessionFromID(sessID)
}

// Logf writes a log line with the provided message.
func (node *Node) Logf(msg string, v ...any) {
	log.Printf("%s | [node] %s\n", node.id, fmt.Sprintf(msg, v...))
}

// func (node *Node) GetNetworkStats() centralized.NetStats {
// 	var stats, srvStats, cliStats centralized.NetStats
// 	if node.srv != nil {
// 		srvStats = node.srv.GetStats()
// 		stats.DataRecv += srvStats.DataRecv
// 		stats.DataSent += srvStats.DataSent
// 	}
// 	if node.cli != nil {
// 		cliStats = node.cli.GetStats()
// 		stats.DataRecv += cliStats.DataRecv
// 		stats.DataSent += cliStats.DataSent
// 	}
// 	return stats
// }

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

// GetCollectivePublicKey returns the collective public key.
func (node *Node) GetCollectivePublicKey(ctx context.Context) (*rlwe.PublicKey, error) {
	if err := node.WaitForSetupDone(ctx); err != nil {
		return nil, fmt.Errorf("error waiting for setup completion: %w", err)
	}
	return node.setup.GetCollectivePublicKey(ctx)
}

// GetGaloisKey returns the Galois keys for galois element galEl.
func (node *Node) GetGaloisKey(ctx context.Context, galEl uint64) (*rlwe.GaloisKey, error) {
	if err := node.WaitForSetupDone(ctx); err != nil {
		return nil, fmt.Errorf("error waiting for setup completion: %w", err)
	}
	return node.setup.GetGaloisKey(ctx, galEl)
}

// GetRelinearizationKey returns the relinearization key.
func (node *Node) GetRelinearizationKey(ctx context.Context) (*rlwe.RelinearizationKey, error) {
	if err := node.WaitForSetupDone(ctx); err != nil {
		return nil, fmt.Errorf("error waiting for setup completion: %w", err)
	}
	return node.setup.GetRelinearizationKey(ctx)
}

// Coordinator interface implementation

// Register is called by the transport upon connection of a new peer node.
func (node *Node) Register(peer helium.NodeID) error {
	if peer == node.id {
		return nil // TODO specific to helper-assisted setting
	}
	return errors.Join(node.setup.Register(peer), node.compute.Register(peer))
}

// Unregister is called by the transport upon disconnection of a peer node.
func (node *Node) Unregister(peer helium.NodeID) error {
	return errors.Join(node.setup.Unregister(peer), node.compute.Unregister(peer))
}

// FHEProvider interface implementation

// GetParameters returns the parameters from the context's session.
func (node *Node) GetParameters(ctx context.Context) (session.FHEParameters, error) {
	return node.compute.GetParameters(ctx)
}

// // GetEncoder returns a lattigo encoder from the context's session.
// func (node *Node) GetEncoder(ctx context.Context) (*bgv.Encoder, error) {
// 	return node.compute.GetEncoder(ctx)
// }

// GetEncryptor returns a lattigo encryptor from the context's session.
// The encryptor is initialized with the collective public key.
func (node *Node) GetEncryptor(ctx context.Context) (*rlwe.Encryptor, error) {
	return node.compute.GetEncryptor(ctx)
}

// GetDecryptor returns a lattigo decryptor from the context's session.
// The decryptor is initialized with the node's secret key.
func (node *Node) GetDecryptor(ctx context.Context) (*rlwe.Decryptor, error) {
	return node.compute.GetDecryptor(ctx)
}

func (node *Node) createNewSession(sessParams session.Parameters) (sess *session.Session, err error) {
	sess, err = node.sessions.NewRLWESession(sessParams, node.id)
	if err != nil {
		return sess, err
	}

	return sess, nil
}

// func (node *Node) sendShares(ctx context.Context) {
// 	for share := range node.outgoingShares {
// 		if err := node.transport.PutShare(ctx, share); err != nil {
// 			node.Logf("error while sending share: %s", err)
// 		}
// 	}
// }
