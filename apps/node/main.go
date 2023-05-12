package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/ldsec/helium/pkg/protocols"
	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"

	"github.com/ldsec/helium/pkg/node"
	"github.com/ldsec/helium/pkg/services/compute"
	"github.com/ldsec/helium/pkg/services/setup"
)

const DefaultAddress = ""

var (
	addr             = flag.String("address", DefaultAddress, "the address on which the node will listen")
	configFile       = flag.String("config", "/helium/config/node.json", "the node config file for this node")
	nodeList         = flag.String("nodes", "/helium/config/nodelist.json", "the node list file")
	setupFile        = flag.String("setup", "/helium/config/setup.json", "the setup description file")
	insecureChannels = flag.Bool("insecureChannels", false, "run the MPC over unauthenticated channels")
	tlsdir           = flag.String("tlsdir", "", "a directory with the required TLS cryptographic material")
	outputMetrics    = flag.Bool("outputMetrics", false, "outputs metrics to a file")
	docompute        = flag.Bool("docompute", false, "whether to execute the compute phase")
	computeFile      = flag.String("compute", "/helium/config/compute.json", "the compute description file")
)

// Instructions to run: go run main.go node.go -config [nodeconfigfile].
func main() {

	flag.Parse()

	if *configFile == "" {
		log.Println("need to provide a config file with the -config flag")
		os.Exit(1)
	}

	var err error
	var nc node.Config
	if err = utils.UnmarshalFromFile(*configFile, &nc); err != nil {
		log.Println("could not read config:", err)
		os.Exit(1)
	}

	if *addr != DefaultAddress || nc.Address == "" {
		// CLI addr overrides config address
		nc.Address = pkg.NodeAddress(*addr)
	}

	if *insecureChannels {
		nc.TLSConfig.InsecureChannels = *insecureChannels
	}

	if *tlsdir != "" {
		nc.TLSConfig.FromDirectory = *tlsdir
	}

	var nl pkg.NodesList
	if err = utils.UnmarshalFromFile(*nodeList, &nl); err != nil {

		log.Println("could not read nodelist:", err)
		os.Exit(1)
	}

	var sd setup.Description
	if *setupFile != "" {
		if err = utils.UnmarshalFromFile(*setupFile, &sd); err != nil {
			log.Printf("could not read setup description file: %s\n", err)
			os.Exit(1)
		}
	}

	node, err := node.NewNode(nc, nl)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	defer func() {
		err := node.Close()
		if err != nil {
			panic(err)
		}
	}()

	// TODO assumes single-session nodes
	if len(nc.SessionParameters) != 1 {
		panic("multi-session nodes not implemented")
	}

	if errConn := node.Connect(); errConn != nil {
		panic(errConn)
	}

	setupPhase(node, nc, sd, nl)

	if *docompute {
		computePhase(node, nc, sd, nl)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	log.Printf("%s | exiting.", nc.ID)
}

func setupPhase(node *node.Node, nc node.Config, sd setup.Description, nl pkg.NodesList) {
	start := time.Now()
	err := node.GetSetupService().Execute(sd, nl)
	if err != nil {
		log.Printf("Node %s | SetupService.Execute() returned an error: %s", nc.ID, err)
	}
	elapsed := time.Since(start)
	outputStats(node, nc, sd, nl, elapsed)
}

func computePhase(node *node.Node, nc node.Config, sd setup.Description, nl pkg.NodesList) {
	// register all circuits in the global state of the compute service
	registerCircuits()

	cloudID := nl[0].NodeID
	var cSign = compute.Signature{
		CircuitName: "PSI",
		Delegate:    cloudID,
	}

	cLabel := pkg.CircuitID("test-circuit-0")
	sessionID := pkg.SessionID(nc.SessionParameters[0].ID)
	sess, exists := node.GetSessionFromID(sessionID)
	if !exists {
		panic(fmt.Errorf("No session found for ID: %s", sessionID))
	}
	ctx := pkg.NewContext(&sessionID, nil)

	computeService := node.GetComputeService()
	err := computeService.LoadCircuit(ctx, cSign, cLabel)
	if err != nil {
		panic(err)
	}

	bfvParams, err := bfv.NewParameters(*sess.Params, 65537)
	if err != nil {
		panic(err)
	}
	kg := rlwe.NewKeyGenerator(*sess.Params)
	_, recPk := kg.GenKeyPair()
	sess.RegisterPkForNode("node-a", *recPk)

	encoder := bfv.NewEncoder(bfvParams)

	ops := []pkg.Operand{}

	// clients
	if node.ID() != cloudID {
		cpk := new(rlwe.PublicKey)
		err = sess.ObjectStore.Load(protocols.Signature{Type: protocols.CKG}.String(), cpk)
		if err != nil {
			panic(fmt.Errorf("%s | CPK was not found for node %s: %s", sess.NodeID, sess.NodeID, err))
		}
		encryptor := bfv.NewEncryptor(bfvParams, cpk)

		// craft input
		var inData []uint64
		if node.ID() == "node-a" {
			inData = []uint64{1, 1, 1, 0, 0}
		} else {
			inData = []uint64{0, 0, 1, 1, 1}
		}
		inPt := encoder.EncodeNew(inData, bfvParams.MaxLevel())
		inCt := encryptor.EncryptNew(inPt)

		// "//nodeID//circuitID/inputID"
		opLabel := pkg.OperandLabel(fmt.Sprintf("//%s/%s/in-0", node.ID(), cLabel))
		ops = append(ops, pkg.Operand{OperandLabel: opLabel, Ciphertext: inCt})
	}

	// execute
	start := time.Now()
	outCtList, err := computeService.Execute(ctx, cLabel, ops...)
	if err != nil {
		panic(fmt.Errorf("[Compute] Client ComputeService.Execute() returned an error: %s", err))
	}
	elapsed := time.Since(start)
	outputStats(node, nc, sd, nl, elapsed)

	// retrieve output
	if len(outCtList) <= 0 {
		log.Println("No outputs to retrieve")
		return
	}
	outCt := outCtList[0]
	if outCt.Ciphertext == nil {
		panic(fmt.Errorf("Output ciphertext is nil"))
	}
	log.Printf("[Compute] Got encrypted output: %v", outCt)
	if sess.Sk == nil {
		log.Printf("Refusing to decrypt output: the session secret key is nil. Is this node supposed to have it?\n")
		return
	}
	decryptor := bfv.NewDecryptor(bfvParams, sess.Sk)
	outPt := encoder.DecodeUintNew(decryptor.DecryptNew(outCt.Ciphertext))[:5]

	log.Printf("[Compute] Retrieved output: %v\n", outPt)
}

func registerCircuits() {
	testCircuits := map[string]compute.Circuit{
		"Identity": func(ec compute.EvaluationContext) error {
			// input from node-a
			opIn := ec.Input("//node-a/in-0")
			_ = ec.Input("//node-b/in-0")

			// output encrypted under CPK
			opRes := pkg.Operand{OperandLabel: "//cloud/out-0", Ciphertext: opIn.Ciphertext}

			// collective key switching
			params := ec.Parameters().Parameters
			opOut, err := ec.CKS("DEC-0", opRes, map[string]string{
				"target":     "node-a",
				"aggregator": "cloud",
				"lvl":        strconv.Itoa(params.MaxLevel()),
				"smudging":   "1.0",
			})
			if err != nil {
				return err
			}

			// output encrypted under node-a public key
			ec.Output(opOut, "node-a")
			return nil
		},
		"PSI": func(ec compute.EvaluationContext) error {
			opIn1 := ec.Input("//node-a/in-0")
			opIn2 := ec.Input("//node-b/in-0")

			// ev := ec.ShallowCopy()
			res := ec.MulNew(opIn1.Ciphertext, opIn2.Ciphertext)
			ec.Relinearize(res, res)
			opRes := pkg.Operand{OperandLabel: "//cloud/out-0", Ciphertext: res}

			params := ec.Parameters().Parameters
			opOut, err := ec.CKS("DEC-0", opRes, map[string]string{
				"target":     "node-a",
				"aggregator": "cloud",
				"lvl":        strconv.Itoa(params.MaxLevel()),
				"smudging":   "1.0",
			})
			if err != nil {
				return err
			}

			ec.Output(opOut, "node-a")
			return nil
		},
	}
	for label, cDef := range testCircuits {
		if err := compute.RegisterCircuit(label, cDef); err != nil {
			panic(err)
		}
	}
}

func outputStats(node *node.Node, nc node.Config, sd setup.Description, nl pkg.NodesList, elapsed time.Duration) {
	log.Printf("%s | finished setup for N=%d T=%d", nc.ID, len(nl), nc.SessionParameters[0].T)
	log.Printf("%s | execute returned after %s", nc.ID, elapsed)
	log.Printf("%s | network stats: %s", nc.ID, node.GetTransport().GetNetworkStats())

	if *outputMetrics {
		var statsJSON []byte
		statsJSON, err := json.MarshalIndent(map[string]string{
			"N":        fmt.Sprint(len(nl)),
			"T":        fmt.Sprint(nc.SessionParameters[0].T),
			"Wall":     fmt.Sprint(elapsed),
			"NetStats": node.GetTransport().GetNetworkStats().String(),
		}, "", "\t")
		if err != nil {
			panic(err)
		}
		if errWrite := os.WriteFile(fmt.Sprintf("/helium/stats/%s.json", nc.ID), statsJSON, 0600); errWrite != nil {
			log.Println(errWrite)
		}
	}
}
