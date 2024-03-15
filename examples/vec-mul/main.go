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
	"github.com/tuneinsight/lattigo/v4/bgv"
	"github.com/tuneinsight/lattigo/v4/drlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

var (

	// sessionParams defines the session parameters for the example application
	sessionParams = session.Parameters{
		ID:    "example-session",                                       // the id of the session must be unique
		Nodes: []helium.NodeID{"node-1", "node-2", "node-3", "node-4"}, // the nodes that will participate in the session
		RLWEParams: bgv.ParametersLiteral{
			T:    79873,
			LogN: 14,
			LogQ: []int{56, 55, 55, 54, 54, 54},
			LogP: []int{55, 55},
		},
		Threshold:  3,
		ShamirPks:  map[helium.NodeID]drlwe.ShamirPublicPoint{"node-1": 1, "node-2": 2, "node-3": 3, "node-4": 4},
		PublicSeed: []byte{'e', 'x', 'a', 'm', 'p', 'l', 'e', 's', 'e', 'e', 'd'},
		Secrets:    nil, // read from /var/run/secrets
	}

	peerNodeConfig = node.Config{
		ID:                "", // read from command line args
		Address:           "", // read from command line args
		HelperID:          "helper",
		SessionParameters: []session.Parameters{sessionParams},
		SetupConfig:       setup.ServiceConfig{Protocols: protocols.ExecutorConfig{MaxParticipation: 1}},
		ComputeConfig:     compute.ServiceConfig{MaxCircuitEvaluation: 1, Protocols: protocols.ExecutorConfig{MaxParticipation: 1}},
		ObjectStoreConfig: objectstore.Config{BackendName: "mem"},
		TLSConfig:         centralized.TLSConfig{InsecureChannels: true},
	}

	helperConfig = node.Config{
		ID:                "", // read from command line args
		Address:           "", // read from command line args
		HelperID:          "helper",
		SessionParameters: []session.Parameters{sessionParams},
		SetupConfig:       setup.ServiceConfig{Protocols: protocols.ExecutorConfig{MaxAggregation: 16, MaxProtoPerNode: 1}},
		ComputeConfig:     compute.ServiceConfig{MaxCircuitEvaluation: 16, Protocols: protocols.ExecutorConfig{MaxAggregation: 16, MaxProtoPerNode: 1}},
		ObjectStoreConfig: objectstore.Config{BackendName: "mem"},
		TLSConfig:         centralized.TLSConfig{InsecureChannels: true},
	}

	nodelist = helium.NodesList{
		helium.NodeInfo{NodeID: "helper", NodeAddress: "helper:40000"},
		helium.NodeInfo{NodeID: "node-1"}, helium.NodeInfo{NodeID: "node-2"},
		helium.NodeInfo{NodeID: "node-3"}, helium.NodeInfo{NodeID: "node-4"}}

	app = node.App{
		SetupDescription: &setup.Description{
			Cpk: true,
			Rlk: true,
		},
		Circuits: map[circuits.Name]circuits.Circuit{
			"mul-4-dec": func(rt circuits.Runtime) error {
				in0, in1, in2, in3 := rt.Input("//p0/in"), rt.Input("//p1/in"), rt.Input("//p2/in"), rt.Input("//p3/in")

				opRes := rt.NewOperand("//eval/prod")
				ctmul01, _ := rt.MulRelinNew(in0.Get().Ciphertext, in1.Get().Ciphertext)
				ctmul23, _ := rt.MulRelinNew(in2.Get().Ciphertext, in3.Get().Ciphertext)
				opRes.Ciphertext, _ = rt.MulRelinNew(ctmul01, ctmul23)

				return rt.DEC(opRes, "rec", map[string]string{
					"smudging": "40.0",
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
		config.SessionParameters[0].Secrets = secrets
	}
	config.ID = nodeID

	ip = func(ctx context.Context, _ helium.CircuitID, ol circuits.OperandLabel, sess session.Session) (any, error) {
		in := make([]uint64, sess.Params.PlaintextSlots())
		for i := range in {
			in[i] = input % sessionParams.RLWEParams.T
		}
		return in, nil
	}

	ctx := helium.NewBackgroundContext(config.SessionParameters[0].ID)
	n, cdescs, outputs, err := node.RunNew(ctx, config, nodelist, app, ip)
	if err != nil {
		log.Fatal(err)
	}

	if nodeID == helperID {
		cdescs <- circuits.Descriptor{
			Signature:   circuits.Signature{Name: circuits.Name("mul-4-dec")},
			CircuitID:   "mul-4-dec-0",
			NodeMapping: map[string]helium.NodeID{"p0": "node-1", "p1": "node-2", "p2": "node-3", "p3": "node-4", "eval": "helper", "rec": "helper"},
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
