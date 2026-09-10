package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/circuits"
	"github.com/ChristianMct/helium/objectstore"
	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/sessions"
	"github.com/tuneinsight/lattigo/v5/mhe"
	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
)

var (
	// sessionParams defines the session parameters for the example application
	sessionParams = sessions.Parameters{
		ID:    "example-session",                                         // the id of the session must be unique
		Nodes: []sessions.NodeID{"node-1", "node-2", "node-3", "node-4"}, // the nodes that will participate in the session
		FHEParameters: bgv.ParametersLiteral{ // the FHE parameters
			LogN:             14,
			LogQ:             []int{56, 55, 55, 54, 54, 54},
			LogP:             []int{55, 55},
			PlaintextModulus: 65537,
		},
		Threshold:  3,                                                                                             // the number of honest nodes assumed by the system.
		ShamirPks:  map[sessions.NodeID]mhe.ShamirPublicPoint{"node-1": 1, "node-2": 2, "node-3": 3, "node-4": 4}, // the shamir public-key of the nodes for the t-out-of-n-threshold scheme.
		PublicSeed: []byte{'e', 'x', 'a', 'm', 'p', 'l', 'e', 's', 'e', 'e', 'd'},                                 // the CRS
	}

	// the configuration of peer nodes
	peerNodeConfig = helium.Config{
		ID:                "",       // read from command line args
		HelperID:          "helper", // the node id of the helper node
		SessionParameters: []sessions.Parameters{sessionParams},

		// in this example, peer node can only participate in one protocol at a time
		ProtocolsConfig: protocols.Config{MaxParticipation: 1},

		ObjectStoreConfig: objectstore.Config{BackendName: "mem"},   // use a volatile in-memory store for state
		TLSConfig:         helium.TLSConfig{InsecureChannels: true}, // no TLS for simplicity
	}

	// the configuration of the helper node. Similar as for peer node, but enables multiple circuit evaluations at once.
	helperConfig = helium.Config{
		ID:                "", // read from command line args
		HelperID:          "helper",
		SessionParameters: []sessions.Parameters{sessionParams},

		// each node is not chosen as participant for more than one protocol at the time.
		CoordinatorConfig: protocols.CoordinatorConfig{MaxProtoPerNode: 1},
		CircuitsConfig:    circuits.Config{MaxEvaluation: 16},
		ObjectStoreConfig: objectstore.Config{BackendName: "mem"},
		TLSConfig:         helium.TLSConfig{InsecureChannels: true},
	}

	// the node list for the example system
	nodelist = helium.List{
		helium.Info{NodeID: "helper", Address: "helper:40000"},
		helium.Info{NodeID: "node-1"}, helium.Info{NodeID: "node-2"},
		helium.Info{NodeID: "node-3"}, helium.Info{NodeID: "node-4"},
	}

	// the application defines the MHE circuits to be evaluated and their required setup
	app = helium.App{
		SetupDescription: &helium.SetupDescription{
			Cpk: true,       // the circuit requires the collective public-key (for encryption)
			Rlk: true,       // the circuit requires the relinearization key (for homomorphic multiplication)
			Gks: []uint64{}, // the circuit does not require any galois keys (for homomorphic rotation)
		},
		Circuits: map[circuits.Name]circuits.Circuit{
			// defines a circuit named "mul-4" that multiplies 4 inputs. Its interface (inputs, outputs
			// and required keys) is derived by symbolic execution of the function: the relinearization
			// key is inferred from the use of MulRelinNew.
			"mul-4": circuits.FromFunc(func(rt circuits.Runtime) error {

				// declares the inputs of the parties. The party ids are place-holders, the mapping to actual
				// node ids is provided when requesting the circuit's evaluation.
				in0, in1, in2, in3 := rt.Input("//p0/in"), rt.Input("//p1/in"), rt.Input("//p2/in"), rt.Input("//p3/in")

				// declares the output of the circuit, owned by the evaluator
				out := rt.Output("prod")

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
				out.Set(res)
				return nil
			}),
		},
	}
)

var (
	nodeID   sessions.NodeID
	nodeAddr helium.Address
	helperID sessions.NodeID = "helper"
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
	var config helium.Config
	if nodeID == helperID {
		config = helperConfig
	} else {
		config = peerNodeConfig
	}
	config.ID = nodeID

	params, err := bgv.NewParametersFromLiteral(sessionParams.FHEParameters.(bgv.ParametersLiteral))
	if err != nil {
		log.Fatalf("%s | [main] error getting session parameters: %v\n", nodeID, err)
	}
	encoder := bgv.NewEncoder(params)

	// creates an InputProvider function from the node's private input
	var ip circuits.InputProvider
	if nodeID == helperID {
		ip = circuits.NoInput // the cloud has no input, the circuits.NoInput InputProvider is used
	} else {
		ip = func(ctx context.Context, cd circuits.Descriptor, ids []circuits.OperandID) (<-chan circuits.Input, error) {
			in := make([]uint64, params.MaxSlots())
			// the session nodes create their input by replicating the user-provided input for each slot
			for i := range in {
				in[i] = input % params.PlaintextModulus()
			}
			inchan := make(chan circuits.Input, len(ids))
			for _, id := range ids {
				inchan <- circuits.Input{ID: id, Value: in}
			}
			close(inchan)
			return inchan, nil
		}
	}

	ctx := sessions.NewBackgroundContext(config.SessionParameters[0].ID)
	start := time.Now()

	if nodeID == helperID {
		runHelper(ctx, config, ip, encoder, params)
	} else {
		runPeer(ctx, config, ip)
	}

	fmt.Printf("TimeStats: %fs\n", time.Since(start).Seconds())
}

// runHelper runs the helper node. The helper acts as the application: it requests the
// evaluation of the circuit, then the decryption of its output to itself.
func runHelper(ctx context.Context, config helium.Config, ip circuits.InputProvider, encoder *bgv.Encoder, params bgv.Parameters) {
	hsv, err := helium.RunHeliumServer(ctx, config, nodelist, app, ip)
	if err != nil {
		log.Fatalf("could not run node: %s", err)
	}

	// requests the evaluation of the circuit
	cd := circuits.Descriptor{
		Signature: circuits.Signature{Name: "mul-4"}, // the name of the circuit to be evaluated
		CircuitID: "mul-4-0",                         // a unique, user-defined id for the circuit evaluation
		NodeMapping: map[string]sessions.NodeID{ // the mapping from party ids in the circuit to actual node ids
			"p0": "node-1",
			"p1": "node-2",
			"p2": "node-3",
			"p3": "node-4",
		},
		Evaluator: "helper", // the id of the circuit evaluator
	}
	if err := hsv.Evaluate(ctx, cd); err != nil {
		log.Fatalf("%s | [main] cannot evaluate circuit: %v\n", nodeID, err)
	}
	if _, err := hsv.Circuits().AwaitCompleted(ctx, cd.CircuitID); err != nil {
		log.Fatalf("%s | [main] circuit evaluation failed: %v\n", nodeID, err)
	}

	// requests the decryption of the output to the helper
	outID := circuits.NewOperandID("helper", cd.CircuitID, "prod")
	decSig := protocols.Signature{Type: protocols.DEC, Args: map[string]string{
		"op":       string(outID),
		"target":   string(helperID),
		"smudging": "40.0", // use 40 bits of smudging.
	}}
	if err := hsv.RunSignature(ctx, decSig); err != nil {
		log.Fatalf("%s | [main] cannot run decryption: %v\n", nodeID, err)
	}
	pd, err := hsv.Protocols().AwaitCompleted(ctx, decSig)
	if err != nil {
		log.Fatalf("%s | [main] decryption failed: %v\n", nodeID, err)
	}
	pt, err := hsv.Protocols().DecryptOutput(ctx, pd)
	if err != nil {
		log.Fatalf("%s | [main] cannot decrypt output: %v\n", nodeID, err)
	}

	res := make([]uint64, params.MaxSlots())
	if err := encoder.Decode(pt, res); err != nil {
		log.Fatalf("%s | [main] error decoding output: %v\n", nodeID, err)
	}
	fmt.Printf("%v\n", res)

	// terminates the coordination
	if err := hsv.Close(ctx); err != nil {
		log.Fatalf("%s | [main] error closing: %v\n", nodeID, err)
	}
	hsv.Wait()
	fmt.Println(hsv.GetStats())
}

// runPeer runs a peer node: it takes part in the setup, provides its input to the circuit
// and to the decryption protocol, until the helper terminates the coordination.
func runPeer(ctx context.Context, config helium.Config, ip circuits.InputProvider) {
	secrets := loadSecrets(config.SessionParameters[0], nodeID)
	hc, err := helium.RunHeliumClient(ctx, config, nodelist, secrets, app, ip)
	if err != nil {
		log.Fatalf("could not run node: %s", err)
	}
	hc.Wait()
	fmt.Println(hc.GetStats())
}

// simulates loading the secrets. In a real application, the secrets would be loaded from a secure storage.
func loadSecrets(params sessions.Parameters, nid sessions.NodeID) helium.SecretProvider {

	var sp helium.SecretProvider = func(sid sessions.ID, nid sessions.NodeID) (*sessions.Secrets, error) {

		if sid != params.ID {
			return nil, fmt.Errorf("no secret for session %s", sid)
		}

		ss, err := sessions.GenTestSecretKeys(params)
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
