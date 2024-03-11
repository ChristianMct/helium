package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"strconv"

	"github.com/ldsec/helium/pkg/circuits"
	"github.com/ldsec/helium/pkg/node"
	"github.com/ldsec/helium/pkg/objectstore"
	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/protocols"
	"github.com/ldsec/helium/pkg/services/compute"
	"github.com/ldsec/helium/pkg/services/setup"
	"github.com/ldsec/helium/pkg/transport/centralized"
	"github.com/tuneinsight/lattigo/v4/bgv"
	"github.com/tuneinsight/lattigo/v4/drlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

var (

	// sessionParams defines the session parameters for the example application
	sessionParams = pkg.SessionParameters{
		ID:    "example-session",                                    // the id of the session must be unique
		Nodes: []pkg.NodeID{"node-1", "node-2", "node-3", "node-4"}, // the nodes that will participate in the session
		RLWEParams: bgv.ParametersLiteral{
			T:    79873,
			LogN: 14,
			LogQ: []int{56, 55, 55, 54, 54, 54},
			LogP: []int{55, 55},
		},
		Threshold:      3,
		ShamirPks:      map[pkg.NodeID]drlwe.ShamirPublicPoint{"node-1": 1, "node-2": 2, "node-3": 3, "node-4": 4},
		PublicSeed:     []byte{'e', 'x', 'a', 'm', 'p', 'l', 'e', 's', 'e', 'e', 'd'},
		SessionSecrets: nil, // read from /var/run/secrets
	}

	peerNodeConfig = node.Config{
		ID:                "", // read from command line args
		Address:           "", // read from command line args
		HelperID:          "helper",
		SessionParameters: []pkg.SessionParameters{sessionParams},
		SetupConfig:       setup.ServiceConfig{Protocols: protocols.ExecutorConfig{MaxParticipation: 1}},
		ComputeConfig:     compute.ServiceConfig{MaxCircuitEvaluation: 1, Protocols: protocols.ExecutorConfig{MaxParticipation: 1}},
		ObjectStoreConfig: objectstore.Config{BackendName: "mem"},
		TLSConfig:         centralized.TLSConfig{InsecureChannels: true},
	}

	helperConfig = node.Config{
		ID:                "", // read from command line args
		Address:           "", // read from command line args
		HelperID:          "helper",
		SessionParameters: []pkg.SessionParameters{sessionParams},
		SetupConfig:       setup.ServiceConfig{Protocols: protocols.ExecutorConfig{MaxAggregation: 16, MaxProtoPerNode: 1}},
		ComputeConfig:     compute.ServiceConfig{MaxCircuitEvaluation: 16, Protocols: protocols.ExecutorConfig{MaxAggregation: 16, MaxProtoPerNode: 1}},
		ObjectStoreConfig: objectstore.Config{BackendName: "mem"},
		TLSConfig:         centralized.TLSConfig{InsecureChannels: true},
	}

	nodelist = pkg.NodesList{
		pkg.NodeInfo{NodeID: "helper", NodeAddress: "helper:40000"},
		pkg.NodeInfo{NodeID: "node-1"}, pkg.NodeInfo{NodeID: "node-2"},
		pkg.NodeInfo{NodeID: "node-3"}, pkg.NodeInfo{NodeID: "node-4"}}

	app = node.App{
		SetupDescription: &setup.Description{ // TODO: remove receivers ?
			Cpk: true,
			Rlk: true,
		},
		Circuits: map[circuits.Name]circuits.Circuit{
			"mul-4-dec": func(ec circuits.Runtime) error {
				in0, in1, in2, in3 := ec.Input("//p0/in"), ec.Input("//p1/in"), ec.Input("//p2/in"), ec.Input("//p3/in")

				opRes := ec.NewOperand("//eval/prod")
				opRes.Ciphertext = bgv.NewCiphertext(ec.Parameters(), 1, ec.Parameters().MaxLevel())
				ctmul01, _ := ec.MulRelinNew(in0.Get().Ciphertext, in1.Get().Ciphertext)
				ctmul23, _ := ec.MulRelinNew(in2.Get().Ciphertext, in3.Get().Ciphertext)
				opRes.Ciphertext, _ = ec.MulRelinNew(ctmul01, ctmul23)

				return ec.DEC(opRes, "rec", map[string]string{
					"lvl":      strconv.Itoa(ec.Parameters().MaxLevel()),
					"smudging": "40.0",
				})
			},
		},
	}
)

var (
	nodeID   pkg.NodeID
	nodeAddr pkg.NodeAddress
	helperID pkg.NodeID = "helper"
	input    uint64
)

func init() {
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

	var config node.Config
	var ip compute.InputProvider
	if nodeID == helperID {
		config = helperConfig
		if len(nodeAddr) == 0 {
			log.Fatal("address of helper node not set, must provide with -address flag")
		}
		config.Address = nodeAddr
	} else {
		config = peerNodeConfig
		if config.SessionParameters[0].Threshold == 0 {
			config.SessionParameters[0].Threshold = len(config.SessionParameters[0].Nodes)
		}
		secrets, err := loadSecrets(config.SessionParameters[0], nodeID)
		if err != nil {
			log.Fatalf("could not load node's secrets: %s", err)
		}
		config.SessionParameters[0].SessionSecrets = secrets
	}
	config.ID = nodeID

	// Create a new node
	n, err := node.NewNode(config, nodelist)
	if err != nil {
		log.Fatal(err)
	}

	sess, _ := n.GetSessionFromID(sessionParams.ID)

	ip = func(ctx context.Context, ol circuits.OperandLabel) (any, error) {
		in := make([]uint64, sess.Params.PlaintextSlots())
		for i := range in {
			in[i] = input % sessionParams.RLWEParams.T
		}
		return in, nil
	}

	if err := n.Connect(context.Background()); err != nil {
		log.Fatal(err)
	}

	ctx := pkg.NewContext(&config.SessionParameters[0].ID, nil)
	cdescs, outputs, err := n.Run(ctx, app, ip)
	if err != nil {
		panic(err)
	}

	if nodeID == helperID {
		cdescs <- circuits.Descriptor{
			Signature:   circuits.Signature{Name: circuits.Name("mul-4-dec")},
			ID:          "mul-4-dec-0",
			NodeMapping: map[string]pkg.NodeID{"p0": "node-1", "p1": "node-2", "p2": "node-3", "p3": "node-4", "eval": "helper", "rec": "helper"},
			Evaluator:   "helper",
		}
	}
	close(cdescs)

	encoder, err := n.GetEncoder(ctx)
	if err != nil {
		log.Fatalf("%s | [main] error getting session encoder: %v\n", nodeID, err)
	}

	out, hasOut := <-outputs

	n.Close()

	if hasOut {
		pt := &rlwe.Plaintext{Operand: out.Ciphertext.Operand, Value: out.Ciphertext.Value[0]}
		res := make([]uint64, encoder.Parameters().PlaintextSlots())
		encoder.Decode(pt, res)
		log.Printf("%s | [main] output: %v\n", nodeID, res)
	}
}

// simulates loading the secrets. In a real application, the secrets would be loaded from a secure storage.
func loadSecrets(sp pkg.SessionParameters, nid pkg.NodeID) (secrets *pkg.SessionSecrets, err error) {

	ss, err := pkg.GenTestSecretKeys(sp)
	if err != nil {
		return nil, err
	}

	secrets, ok := ss[nid]
	if !ok {
		return nil, fmt.Errorf("node %s not in session", nid)
	}

	return
	// data, err := os.ReadFile(fmt.Sprintf("/run/secrets/secret_%s", nodeID))
	// if err != nil {
	// 	return nil, err
	// }

	// lines := strings.Split(string(data), "\n")

	// secrets = new(pkg.SessionSecrets)
	// secrets.PrivateSeed = []byte(lines[0])

	// if threshold {
	// 	if len(lines) < 2 {
	// 		return nil, fmt.Errorf("invalid secret file for threshold < N: expected 2 lines, got %d", len(lines))
	// 	}

	// 	secrets.ThresholdSecretKey = &drlwe.ShamirSecretShare{}
	// 	tskdata, err := base64.StdEncoding.DecodeString(lines[1])
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	err = secrets.ThresholdSecretKey.UnmarshalBinary(tskdata)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	//}
}
