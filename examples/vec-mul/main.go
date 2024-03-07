package main

import (
	"context"
	"flag"
	"log"
	"strconv"
	"unicode"

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
	sessionParams = pkg.SessionParameters{
		ID:          "example-session",
		Nodes:       []pkg.NodeID{"node-1", "node-2", "node-3", "node-4"},
		RLWEParams:  bgv.ParametersLiteral{T: 79873, LogN: 12, LogQ: []int{30, 30, 39, 31}, LogP: []int{39}},
		T:           4,
		ShamirPks:   map[pkg.NodeID]drlwe.ShamirPublicPoint{"node-1": 1, "node-2": 2, "node-3": 3, "node-4": 4},
		PublicSeed:  []byte{'e', 'x', 'a', 'm', 'p', 'l', 'e', 's', 'e', 'e', 'd'},
		PrivateSeed: []byte{}, // read from helium secret file
	}

	lightNodeConfig = node.Config{
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
			Cpk: sessionParams.Nodes,
			Rlk: []pkg.NodeID{"helper"},
		},
		Circuits: map[circuits.Name]circuits.Circuit{
			"mul-4-dec": func(ec circuits.EvaluationContext) error {
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
)

func init() {
	flag.StringVar((*string)(&nodeID), "id", "", "the node's id")
	flag.StringVar((*string)(&nodeAddr), "address", "", "the node's address")
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
		config = lightNodeConfig
		config.SessionParameters[0].PrivateSeed = []byte("secret") // TODO read from helium secret file
	}
	config.ID = nodeID

	// Create a new node
	n, err := node.NewNode(config, nodelist)
	if err != nil {
		log.Fatal(err)
	}

	ip = func(ctx context.Context, ol circuits.OperandLabel) (any, error) {
		olr, err := pkg.ParseURL(string(ol))
		if err != nil {
			return nil, err
		}
		nidInt := extractFirstInteger(string(olr.NodeID()))
		cidInt := extractFirstInteger(string(olr.CircuitID()))
		return []uint64{(nidInt * cidInt) % sessionParams.RLWEParams.T}, nil
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
	for out := range outputs {
		pt := &rlwe.Plaintext{Operand: out.Ciphertext.Operand, Value: out.Ciphertext.Value[0]}
		res := make([]uint64, encoder.Parameters().PlaintextSlots())
		encoder.Decode(pt, res)
		log.Printf("%s | [main] output: %v\n", nodeID, res)
	}
	n.Close()
}

func extractFirstInteger(s string) uint64 {
	var start, stop int
	for start = 0; start < len(s) && !unicode.IsDigit(rune(s[start])); start++ {
	}
	for stop = start; stop < len(s) && unicode.IsDigit(rune(s[stop])); stop++ {
	}
	if i, err := strconv.ParseUint(s[start:stop], 10, 64); err == nil {
		return i
	}
	return 0
}
