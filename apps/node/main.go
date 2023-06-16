package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
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
	docompute        = flag.Bool("docompute", true, "executes the compute phase")
	computeFile      = flag.String("compute", "/helium/config/compute.json", "the compute description file")
)

type App struct {
	nc   node.Config
	nl   pkg.NodesList
	sd   setup.Description
	cd   compute.Description
	node *node.Node
	sess *pkg.Session
}

// Instructions to run: go run main.go node.go -config [nodeconfigfile].
func main() {

	flag.Parse()

	// if *configFile == "" {
	// 	log.Println("need to provide a config file with the -config flag")
	// 	os.Exit(1)
	// }

	// app holds all data relative to the node execution.
	app := App{}

	var err error
	if err = utils.UnmarshalFromFile(*configFile, &app.nc); err != nil {
		log.Println("could not read config:", err)
		os.Exit(1)
	}

	if *addr != DefaultAddress || app.nc.Address == "" {
		// CLI addr overrides config address
		app.nc.Address = pkg.NodeAddress(*addr)
	}

	if *insecureChannels {
		app.nc.TLSConfig.InsecureChannels = *insecureChannels
	}

	if *tlsdir != "" {
		app.nc.TLSConfig.FromDirectory = *tlsdir
	}

	if err = utils.UnmarshalFromFile(*nodeList, &app.nl); err != nil {
		log.Println("could not read nodelist:", err)
		os.Exit(1)
	}

	app.node, err = node.NewNode(app.nc, app.nl)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	defer func() {
		err := app.node.Close()
		if err != nil {
			panic(err)
		}
	}()

	// TODO assumes single-session nodes
	if len(app.nc.SessionParameters) != 1 {
		panic("multi-session nodes not implemented")
	}

	sessionID := pkg.SessionID(app.nc.SessionParameters[0].ID)
	var exists bool
	app.sess, exists = app.node.GetSessionFromID(sessionID)
	if !exists {
		panic(fmt.Errorf("No session found for ID: %s", sessionID))
	}

	var cloudID pkg.NodeID
	var cLabel pkg.CircuitID
	var cSign compute.Signature
	var ctx context.Context
	var computeService *compute.Service
	if *docompute {
		// parse compute description
		if err = utils.UnmarshalFromFile(*computeFile, &app.cd); err != nil {
			log.Printf("could not read compute description file: %s\n", err)
			os.Exit(1)
		}

		// Register and load circuit.
		// The cloud is defined as the first node of the nodelist.
		// We need to load the circuit before the cloud goes online so that clients do not query for unexpected ciphertexts.
		app.registerCircuits()
		cloudID = app.nl[0].NodeID
		cLabel = pkg.CircuitID("test-circuit-0")
		cSign = compute.Signature{
			CircuitName: app.cd.CircuitName,
			Delegate:    cloudID,
		}
		ctx = pkg.NewContext(&app.sess.ID, nil)
		computeService = app.node.GetComputeService()

		err = computeService.LoadCircuit(ctx, cSign, cLabel)
		if err != nil {
			panic(err)
		}

		// infer setup description
		app.sd, err = setup.ComputeDescriptionToSetupDescription(computeService.CircuitDescription(cLabel))
		if err != nil {
			panic(err)
		}
	} else {
		// parse setup description
		if err = utils.UnmarshalFromFile(*setupFile, &app.sd); err != nil {
			log.Printf("could not read setup description file: %s\n", err)
			os.Exit(1)
		}
	}

	log.Printf("%s | connecting...\n", app.nc.ID)
	if errConn := app.node.Connect(); errConn != nil {
		panic(errConn)
	}

	// SETUP
	app.setupPhase()

	// COMPUTE
	if *docompute {
		app.computePhase(cloudID, ctx, cLabel, cSign)
	}

	// sigs := make(chan os.Signal, 1)
	// signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	// <-sigs
	<-time.After(time.Second)
	log.Printf("%s | exiting.", app.nc.ID)
}

// setupPhase executes the setup phase of Helium.
func (a *App) setupPhase() {
	start := time.Now()
	err := a.node.GetSetupService().Execute(a.sd, a.nl)
	if err != nil {
		log.Printf("Node %s | SetupService.Execute() returned an error: %s", a.nc.ID, err)
	}
	elapsed := time.Since(start)
	a.outputStats(a.cd.CircuitName, "setup", elapsed)
}

// computePhase executes the computational phase of Helium.
func (a *App) computePhase(cloudID pkg.NodeID, ctx context.Context, cLabel pkg.CircuitID, cSign compute.Signature) {
	bfvParams, err := bfv.NewParameters(*a.sess.Params, 65537)
	if err != nil {
		panic(err)
	}

	encoder := bfv.NewEncoder(bfvParams)

	ops := []pkg.Operand{}

	// craft input for session nodes
	if utils.NewSet(a.sess.Nodes).Contains(a.node.ID()) {
		switch cSign.CircuitName {
		case "psi-2", "psi-4", "psi-8", "psi-2-PCKS":
			ops = a.getClientOperandsPSI(bfvParams, encoder, cLabel)
		case "pir-3", "pir-5", "pir-9":
			ops = a.getClientOperandsPIR(bfvParams, encoder, cLabel)
		default:
			panic(fmt.Errorf("unknown circuit name: %s", cSign.CircuitName))
		}
	}

	computeService := a.node.GetComputeService()
	// execute
	start := time.Now()
	outCtList, err := computeService.Execute(ctx, cLabel, ops...)
	if err != nil {
		panic(fmt.Errorf("[Compute] Client ComputeService.Execute() returned an error: %w", err))
	}
	elapsed := time.Since(start)
	a.outputStats(a.cd.CircuitName, "compute", elapsed)

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

	var outputSk *rlwe.SecretKey

	externalReceivers := make(utils.Set[pkg.NodeID])
	for _, externalReceiver := range a.sd.Pk {
		externalReceivers.Add(externalReceiver.Sender)
	}

	if externalReceivers.Contains(a.node.ID()) {
		outputSk, err = a.sess.OutputSk()
		if err != nil {
			panic(err)
		}
	} else {
		if a.sess.Sk == nil {
			log.Printf("error while decrypting output: the session secret key is nil. Is this node (%s) the indended receiver?\n", a.node.ID())
			return
		}
		outputSk = a.sess.Sk
	}

	decryptor := bfv.NewDecryptor(bfvParams, outputSk)
	outPt := encoder.DecodeUintNew(decryptor.DecryptNew(outCt.Ciphertext))[:8]

	log.Printf("[Compute] Retrieved output: %v\n", outPt)
}

// getClientOperandsPSI returns the operands that this client node will input into the PSI computation.
func (a *App) getClientOperandsPSI(bfvParams bfv.Parameters, encoder bfv.Encoder, cLabel pkg.CircuitID) []pkg.Operand {
	ops := []pkg.Operand{}
	cpk := new(rlwe.PublicKey)
	err := a.sess.ObjectStore.Load(protocols.Signature{Type: protocols.CKG}.String(), cpk)
	if err != nil {
		panic(fmt.Errorf("%s | CPK was not found for node %s: %s", a.sess.NodeID, a.sess.NodeID, err))
	}
	encryptor := bfv.NewEncryptor(bfvParams, cpk)

	// craft input
	inData := [8]uint64{1, 1, 1, 1, 1, 1, 1, 1}
	val, err := strconv.Atoi(strings.Split(string(a.node.ID()), "-")[1])
	if err != nil {
		panic(err)
	}
	inData[val] = uint64(val)
	inPt := encoder.EncodeNew(inData[:], bfvParams.MaxLevel())
	inCt := encryptor.EncryptNew(inPt)

	// "//nodeID//circuitID/inputID"
	opLabel := pkg.OperandLabel(fmt.Sprintf("//%s/%s/in-0", a.node.ID(), cLabel))
	ops = append(ops, pkg.Operand{OperandLabel: opLabel, Ciphertext: inCt})

	return ops
}

// getClientOperandsPIR returns the operands that this client node will input into the PIR computation.
func (a *App) getClientOperandsPIR(bfvParams bfv.Parameters, encoder bfv.Encoder, cLabel pkg.CircuitID) []pkg.Operand {
	ops := []pkg.Operand{}
	cpk := new(rlwe.PublicKey)
	err := a.sess.ObjectStore.Load(protocols.Signature{Type: protocols.CKG}.String(), cpk)
	if err != nil {
		panic(fmt.Errorf("%s | CPK was not found for node %s: %s", a.sess.NodeID, a.sess.NodeID, err))
	}
	encryptor := bfv.NewEncryptor(bfvParams, cpk)

	// craft input
	inData := make([]uint64, bfvParams.N())

	reqFromNode := 2

	if a.node.ID() == "node-0" {
		inData[reqFromNode] = 1
	} else {
		val, err := strconv.Atoi(strings.Split(string(a.node.ID()), "-")[1])
		if err != nil {
			panic(err)
		}
		for i := range inData {
			inData[i] = uint64(val)
		}
	}
	inPt := encoder.EncodeNew(inData, bfvParams.MaxLevel())
	inCt := encryptor.EncryptNew(inPt)

	// "//nodeID//circuitID/inputID"
	opLabel := pkg.OperandLabel(fmt.Sprintf("//%s/%s/in-0", a.node.ID(), cLabel))
	ops = append(ops, pkg.Operand{OperandLabel: opLabel, Ciphertext: inCt})

	return ops
}

// registerCircuits registers some predefined circuits in the global state of the compute service.
func (a *App) registerCircuits() {

	for label, cDef := range testCircuits {
		if err := compute.RegisterCircuit(label, cDef); err != nil {
			panic(err)
		}
	}
}

// outputStats outputs the total network usage and time take to execute a protocol phase.
func (a *App) outputStats(circuit, phase string, elapsed time.Duration) {
	log.Println("==============", phase, "phase ==============")
	log.Printf("%s | finished setup for N=%d T=%d", a.nc.ID, len(a.nl), a.nc.SessionParameters[0].T)
	log.Printf("%s | execute returned after %s", a.nc.ID, elapsed)
	log.Printf("%s | network stats: %s\n", a.nc.ID, a.node.GetTransport().GetNetworkStats())

	if *outputMetrics {
		var statsJSON []byte
		statsJSON, err := json.MarshalIndent(map[string]string{
			"Wall":    fmt.Sprint(elapsed),
			"Sent":    fmt.Sprint(a.node.GetTransport().GetNetworkStats().DataSent),
			"Recvt":   fmt.Sprint(a.node.GetTransport().GetNetworkStats().DataRecv),
			"N":       fmt.Sprint(len(a.sess.Nodes)),
			"T":       fmt.Sprint(a.nc.SessionParameters[0].T),
			"ID":      fmt.Sprint(a.nc.ID),
			"Circuit": circuit,
			"Phase":   phase,
		}, "", "\t")
		if err != nil {
			panic(err)
		}
		if errWrite := os.WriteFile(fmt.Sprintf("/helium/stats/%s-%s-%s.json", circuit, phase, a.nc.ID), statsJSON, 0600); errWrite != nil {
			log.Println(errWrite)
		}
	}
}
