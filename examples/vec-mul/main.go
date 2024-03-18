package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/circuits"
	"github.com/ChristianMct/helium/node"
	"github.com/ChristianMct/helium/objectstore"
	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/services/compute"
	"github.com/ChristianMct/helium/services/setup"
	"github.com/ChristianMct/helium/session"
	"github.com/ChristianMct/helium/transport/centralized"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	drlwe "github.com/tuneinsight/lattigo/v5/mhe"
	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
)

var (
	// sessionParams defines the session parameters for the example application
	sessionParams = session.Parameters{
		ID:    "example-session",                                       // the id of the session must be unique
		Nodes: []helium.NodeID{"node-1", "node-2", "node-3", "node-4"}, // the nodes that will participate in the session
		RLWEParams: bgv.ParametersLiteral{ // the FHE parameters
			PlaintextModulus: 79873,
			LogN:             14,
			LogQ:             []int{56, 55, 55, 54, 54, 54},
			LogP:             []int{55, 55},
		},
		Threshold:  3,                                                                                             // the number of honest nodes assumed by the system.
		ShamirPks:  map[helium.NodeID]drlwe.ShamirPublicPoint{"node-1": 1, "node-2": 2, "node-3": 3, "node-4": 4}, // the shamir public-key of the nodes for the t-out-of-n-threshold scheme.
		PublicSeed: []byte{'e', 'x', 'a', 'm', 'p', 'l', 'e', 's', 'e', 'e', 'd'},                                 // the CRS
		Secrets:    nil,                                                                                           // normally read from a file, simulated here for simplicity (see loadSecrets)
	}

	// the configuration of peer nodes
	peerNodeConfig = node.Config{
		ID:                "",       // read from command line args
		Address:           "",       // read from command line args
		HelperID:          "helper", // the node id of the helper node
		SessionParameters: []session.Parameters{sessionParams},

		// in this example, peer node can only participate in one protocol and one circuit at a time
		SetupConfig:   setup.ServiceConfig{Protocols: protocols.ExecutorConfig{MaxParticipation: 1}},
		ComputeConfig: compute.ServiceConfig{MaxCircuitEvaluation: 1, Protocols: protocols.ExecutorConfig{MaxParticipation: 1}},

		ObjectStoreConfig: objectstore.Config{BackendName: "mem"},        // use a volatile in-memory store for state
		TLSConfig:         centralized.TLSConfig{InsecureChannels: true}, // no TLS for simplicity
	}

	// the configuration of the helper node. Similar as for peer node, but enables multiple protocol and circuit evaluations at once.
	helperConfig = node.Config{
		ID:                "", // read from command line args
		Address:           "", // read from command line args
		HelperID:          "helper",
		SessionParameters: []session.Parameters{sessionParams},

		// allows 16 parallel protocol aggregation and each node is not chosen as participant for more than one protocol at the time.
		SetupConfig:       setup.ServiceConfig{Protocols: protocols.ExecutorConfig{MaxAggregation: 16, MaxProtoPerNode: 1}},
		ComputeConfig:     compute.ServiceConfig{MaxCircuitEvaluation: 16, Protocols: protocols.ExecutorConfig{MaxAggregation: 16, MaxProtoPerNode: 1}},
		ObjectStoreConfig: objectstore.Config{BackendName: "mem"},
		TLSConfig:         centralized.TLSConfig{InsecureChannels: true},
	}

	// the node list for the example system
	nodelist = helium.NodesList{
		helium.NodeInfo{NodeID: "helper", NodeAddress: "helper:40000"},
		helium.NodeInfo{NodeID: "node-1"}, helium.NodeInfo{NodeID: "node-2"},
		helium.NodeInfo{NodeID: "node-3"}, helium.NodeInfo{NodeID: "node-4"},
	}

	// the application defines the MHE circuit to be evaluated and its required setup
	app = node.App{
		SetupDescription: &setup.Description{
			Cpk: true,       // the circuit requires the collective public-key (for encryption)
			Rlk: true,       // the circuit requires the relinearization key (for homomorphic multiplication)
			Gks: []uint64{}, // the circuit does not require any galois keys (for homomorphic rotation)
		},
		Circuits: map[circuits.Name]circuits.Circuit{
			// defines a circuit named "mul-4-dec" that multiplies 4 inputs and decrypts the result
			"mul-4-dec": func(rt circuits.Runtime) error {

				// reads the inputs from the parties. The node ids can be place-holders and the mapping actual ids are provided
				// when querying for a circuit's execution.
				in0, in1, in2, in3 := rt.Input("//p0/in"), rt.Input("//p1/in"), rt.Input("//p2/in"), rt.Input("//p3/in")

				// computes the product between all inputs
				opRes := rt.NewOperand("//eval/prod")
				ctmul01, _ := rt.MulRelinNew(in0.Get().Ciphertext, in1.Get().Ciphertext)
				ctmul23, _ := rt.MulRelinNew(in2.Get().Ciphertext, in3.Get().Ciphertext)
				opRes.Ciphertext, _ = rt.MulRelinNew(ctmul01, ctmul23)

				// decrypts the result with result receiver id "rec". The node id can be a place-holder and the actual id is provided
				// when querying for a circuit's execution.
				return rt.DEC(opRes, "rec", map[string]string{
					"smudging": "40.0", // use 40 bits of smudging.
				})
			},
		},
	}
)

var (
	nodeID   helium.NodeID
	nodeAddr helium.NodeAddress
	helperID helium.NodeID = "helper"
	input    uint64
)

func init() {
	// registers the command line arguments
	flag.StringVar((*string)(&nodeID), "id", "", "the node's id")
	flag.StringVar((*string)(&nodeAddr), "address", "", "the node's address")
	flag.Uint64Var(&input, "input", 0, "the private input value")
}

func main() {
	flag.Parse()

	if len(nodeID) == 0 {
		log.Fatal("id of node not set, must provide with -id flag")

	}

	log.Printf("%s | [main] started\n", nodeID)

	// completes the config according to the node id
	var config node.Config
	if nodeID == helperID {
		config = helperConfig
		if len(nodeAddr) == 0 {
			log.Fatal("address of helper node not set, must provide with -address flag")
		}
		config.Address = nodeAddr
	} else {
		config = peerNodeConfig
		secrets, err := loadSecrets(config.SessionParameters[0], nodeID) // session node must load their secrets.
		if err != nil {
			log.Fatalf("could not load node's secrets: %s", err)
		}
		config.SessionParameters[0].Secrets = secrets
	}
	config.ID = nodeID

	// creates an InputProvider function from the node's private input
	ip := func(ctx context.Context, _ helium.CircuitID, ol circuits.OperandLabel, sess session.Session) (any, error) {
		in := make([]uint64, sess.Params.MaxSlots())
		for i := range in {
			in[i] = input % sess.RLWEParams.PlaintextModulus
		}
		return in, nil
	}

	// runs the app on a new node
	ctx := helium.NewBackgroundContext(config.SessionParameters[0].ID)
	n, cdescs, outputs, err := node.RunNew(ctx, config, nodelist, app, ip)
	if err != nil {
		log.Fatal(err)
	}

	// the helper node starts the computation by sending a circuit description to the cdescs channel
	if nodeID == helperID {
		cdescs <- circuits.Descriptor{
			Signature: circuits.Signature{Name: circuits.Name("mul-4-dec")}, // the name of the circuit to be evaluated
			CircuitID: "mul-4-dec-0",                                        // a unique, user-defined id for the circuit
			NodeMapping: map[string]helium.NodeID{ // the mapping from node ids in the circuit to actual node ids
				"p0":   "node-1",
				"p1":   "node-2",
				"p2":   "node-3",
				"p3":   "node-4",
				"eval": "helper",
				"rec":  "helper"},
			Evaluator: "helper", // the id of the circuit evaluator
		}
	}
	close(cdescs) // when no more circuits evaluation are required, the user closes the cdesc channel

	params, err := n.GetParameters(ctx)
	if err != nil {
		log.Fatalf("%s | [main] error getting session parameters: %v\n", nodeID, err)
	}

	encoder, err := n.GetEncoder(ctx)
	if err != nil {
		log.Fatalf("%s | [main] error getting session encoder: %v\n", nodeID, err)
	}

	// outputs are received on the outputs channel. The output is a Lattigo rlwe.Plaintext.
	out, hasOut := <-outputs

	n.Close()

	if hasOut {
		pt := &rlwe.Plaintext{Element: out.Ciphertext.Element, Value: out.Ciphertext.Value[0]}
		res := make([]uint64, params.MaxSlots())
		encoder.Decode(pt, res)
		fmt.Printf("%v\n", res)
	}
}

// simulates loading the secrets. In a real application, the secrets would be loaded from a secure storage.
func loadSecrets(sp session.Parameters, nid helium.NodeID) (secrets *session.Secrets, err error) {

	ss, err := session.GenTestSecretKeys(sp)
	if err != nil {
		return nil, err
	}

	secrets, ok := ss[nid]
	if !ok {
		return nil, fmt.Errorf("node %s not in session", nid)
	}

	return
}
