package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/heliumtest"
	"github.com/ChristianMct/helium/helper"
	"github.com/tuneinsight/lattigo/v5/mhe"
	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
)

var (
	// sessionParams defines the session parameters for the example application
	sessionParams = helium.Parameters{
		ID:    "example-session",                                       // the id of the session must be unique
		Nodes: []helium.NodeID{"node-1", "node-2", "node-3", "node-4"}, // the nodes that will participate in the session
		FHEParameters: bgv.ParametersLiteral{ // the FHE parameters
			LogN:             14,
			LogQ:             []int{56, 55, 55, 54, 54, 54},
			LogP:             []int{55, 55},
			PlaintextModulus: 65537,
		},
		Threshold:  3,                                                                                           // the number of honest nodes assumed by the system.
		ShamirPks:  map[helium.NodeID]mhe.ShamirPublicPoint{"node-1": 1, "node-2": 2, "node-3": 3, "node-4": 4}, // the shamir public-key of the nodes for the t-out-of-n-threshold scheme.
		PublicSeed: []byte{'e', 'x', 'a', 'm', 'p', 'l', 'e', 's', 'e', 'e', 'd'},                               // the CRS
	}

	// the configuration of peer nodes
	peerNodeConfig = helper.Config{
		Config: helium.Config{
			ID:                "", // read from command line args
			SessionParameters: sessionParams,
			// in this example, peer node can only participate in one protocol at a time
			MaxParticipation: 1,
			ObjectStore:      helium.ObjectStoreConfig{BackendName: "mem"}, // use a volatile in-memory store for state
		},
		HelperID: "helper",                                 // the node id of the helper node
		TLS:      helper.TLSConfig{InsecureChannels: true}, // no TLS for simplicity
	}

	// the configuration of the helper node. Similar as for peer node, but enables multiple circuit evaluations at once.
	helperConfig = helper.Config{
		Config: helium.Config{
			ID:                "", // read from command line args
			SessionParameters: sessionParams,
			MaxEvaluation:     16,
			ObjectStore:       helium.ObjectStoreConfig{BackendName: "mem"},
		},
		HelperID: "helper",
		// each node is not chosen as participant for more than one protocol at the time.
		MaxProtoPerNode: 1,
		TLS:             helper.TLSConfig{InsecureChannels: true},
	}

	// the node list for the example system
	nodelist = helium.NodeList{
		helium.NodeInfo{NodeID: "helper", NodeAddress: "helper:40000"},
		helium.NodeInfo{NodeID: "node-1"}, helium.NodeInfo{NodeID: "node-2"},
		helium.NodeInfo{NodeID: "node-3"}, helium.NodeInfo{NodeID: "node-4"},
	}

	// the application defines the MHE circuits to be evaluated, their required setup, and the
	// Main function run by every node.
	app = helium.App{
		Setup: &helium.SetupDescription{
			Cpk: true,       // the circuit requires the collective public-key (for encryption)
			Rlk: true,       // the circuit requires the relinearization key (for homomorphic multiplication)
			Gks: []uint64{}, // the circuit does not require any galois keys (for homomorphic rotation)
		},
		Circuits: map[helium.Name]helium.Circuit{
			// defines a circuit named "mul-4" that multiplies 4 inputs. Its interface (inputs, outputs
			// and required keys) is derived by symbolic execution of the function: the relinearization
			// key is inferred from the use of MulRelinNew.
			"mul-4": helium.FromFunc(func(rt helium.CircuitRuntime) error {

				// declares the inputs of the parties. The party ids are place-holders, the mapping to actual
				// node ids is provided when requesting the circuit's evaluation.
				in0, in1, in2, in3 := rt.Input("//p0/in"), rt.Input("//p1/in"), rt.Input("//p2/in"), rt.Input("//p3/in")

				// computes the product between all inputs
				eval := rt.Evaluator()
				ctmul01, err := eval.MulRelinNew(in0.Get().Ciphertext, in1.Get().Ciphertext)
				if err != nil {
					return err
				}
				ctmul23, err := eval.MulRelinNew(in2.Get().Ciphertext, in3.Get().Ciphertext)
				if err != nil {
					return err
				}
				res, err := eval.MulRelinNew(ctmul01, ctmul23)
				if err != nil {
					return err
				}
				rt.Output("prod").Set(res)
				return nil
			}),
		},
		// the application's Main function: every node runs it, the helper acting as the evaluator
		// and the peers providing their inputs
		Main: func(ctx context.Context, rt helium.Runtime) error {

			params := rt.Parameters().(bgv.Parameters)

			// the session nodes create their input by replicating the user-provided input for each slot
			var inputs map[string]any
			if rt.ID() != helperID {
				in := make([]uint64, params.MaxSlots())
				for i := range in {
					in[i] = input % params.PlaintextModulus()
				}
				inputs = map[string]any{"in": in}
			}

			// evaluates the circuit: the helper evaluates it, the peers provide their input
			outs, err := rt.Evaluate(ctx,
				helium.Descriptor{
					Signature: helium.Signature{Name: "mul-4"}, // the name of the circuit to be evaluated
					CircuitID: "mul-4-0",                       // a unique, user-defined id for the circuit evaluation
					NodeMapping: map[string]helium.NodeID{ // the mapping from party ids in the circuit to actual node ids
						"p0": "node-1",
						"p1": "node-2",
						"p2": "node-3",
						"p3": "node-4",
					},
					Evaluator: "helper", // the id of the circuit evaluator
				}, inputs)
			if err != nil {
				return fmt.Errorf("cannot evaluate circuit: %w", err)
			}

			// decrypts the output "prod" to the helper, with 40 bits of smudging noise
			pt, err := rt.Decrypt(ctx, outs["prod"], helperID, 40)
			if err != nil {
				return fmt.Errorf("cannot decrypt output: %w", err)
			}

			// the helper decodes and prints the result
			if rt.ID() == helperID {
				res := make([]uint64, params.MaxSlots())
				if err := bgv.NewEncoder(params).Decode(pt, res); err != nil {
					return fmt.Errorf("error decoding output: %w", err)
				}
				fmt.Printf("%v\n", res)
			}
			return nil
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
	var config helper.Config
	if nodeID == helperID {
		config = helperConfig
	} else {
		config = peerNodeConfig
	}
	config.ID = nodeID

	ctx := context.Background()
	start := time.Now()

	if nodeID == helperID {
		hsv, err := helper.RunServer(ctx, config, nodelist, app)
		if err != nil {
			log.Fatalf("%s | [main] error running node: %v\n", nodeID, err)
		}
		fmt.Println(hsv.GetStats())
		hsv.GracefulStop()
	} else {
		hc, err := helper.RunClient(ctx, config, nodelist, loadSecrets(sessionParams, nodeID), app)
		if err != nil {
			log.Fatalf("%s | [main] error running node: %v\n", nodeID, err)
		}
		fmt.Println(hc.GetStats())
	}

	fmt.Printf("TimeStats: %fs\n", time.Since(start).Seconds())
}

// simulates loading the secrets. In a real application, the secrets would be loaded from a secure storage.
func loadSecrets(params helium.Parameters, nid helium.NodeID) helium.SecretProvider {

	var sp helium.SecretProvider = func(sid helium.SessionID, nid helium.NodeID) (*helium.Secrets, error) {

		if sid != params.ID {
			return nil, fmt.Errorf("no secret for session %s", sid)
		}

		ss, err := heliumtest.GenSecretKeys(params)
		if err != nil {
			return nil, err
		}

		secrets, ok := ss[nid]
		if !ok {
			return nil, fmt.Errorf("node %s not in session", nid)
		}

		return secrets, nil
	}

	return sp
}
