package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
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

	if *configFile == "" {
		log.Println("need to provide a config file with the -config flag")
		os.Exit(1)
	}

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

	if *setupFile != "" {
		if err = utils.UnmarshalFromFile(*setupFile, &app.sd); err != nil {
			log.Printf("could not read setup description file: %s\n", err)
			os.Exit(1)
		}
	}

	if *computeFile != "" {
		if err = utils.UnmarshalFromFile(*computeFile, &app.cd); err != nil {
			log.Printf("could not read compute description file: %s\n", err)
			os.Exit(1)
		}
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

	registerCircuits()
	cloudID := app.nl[0].NodeID
	cLabel := pkg.CircuitID("test-circuit-0")
	var cSign = compute.Signature{
		CircuitName: app.cd.CircuitName,
		Delegate:    cloudID,
	}
	ctx := pkg.NewContext(&app.sess.ID, nil)
	computeService := app.node.GetComputeService()
	err = computeService.LoadCircuit(ctx, cSign, cLabel)
	if err != nil {
		panic(err)
	}

	if errConn := app.node.Connect(); errConn != nil {
		panic(errConn)
	}

	app.setupPhase()

	if *docompute {
		app.computePhase()
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
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
	a.outputStats("setup", elapsed)
}

// computePhase executes the computational phase of Helium.
func (a *App) computePhase() {

	cloudID := a.nl[0].NodeID
	cLabel := pkg.CircuitID("test-circuit-0")
	var cSign = compute.Signature{
		CircuitName: a.cd.CircuitName,
		Delegate:    cloudID,
	}
	ctx := pkg.NewContext(&a.sess.ID, nil)

	bfvParams, err := bfv.NewParameters(*a.sess.Params, 65537)
	if err != nil {
		panic(err)
	}
	// kg := rlwe.NewKeyGenerator(*a.sess.Params)
	// _, recPk := kg.GenKeyPair()
	// a.sess.RegisterPkForNode("receiver", *recPk)

	encoder := bfv.NewEncoder(bfvParams)

	ops := []pkg.Operand{}

	// craft input for clients
	if a.node.ID() != cloudID {
		switch cSign.CircuitName {
		case "psi-2":
			ops = a.getClientOperandsPSI(bfvParams, encoder, cLabel)
		case "pir-3":
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
		panic(fmt.Errorf("[Compute] Client ComputeService.Execute() returned an error: %s", err))
	}
	elapsed := time.Since(start)
	a.outputStats("compute", elapsed)

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
	if a.sess.Sk == nil {
		log.Printf("Refusing to decrypt output: the session secret key is nil. Is this node supposed to have it?\n")
		return
	}
	decryptor := bfv.NewDecryptor(bfvParams, a.sess.Sk)
	outPt := encoder.DecodeUintNew(decryptor.DecryptNew(outCt.Ciphertext))[:8]

	log.Printf("[Compute] Retrieved output: %v\n", outPt)
}

// getClientOperands returns the operands that this client node will input into the computation.
func (a *App) getClientOperandsPSI(bfvParams bfv.Parameters, encoder bfv.Encoder, cLabel pkg.CircuitID) []pkg.Operand {
	ops := []pkg.Operand{}
	cpk := new(rlwe.PublicKey)
	err := a.sess.ObjectStore.Load(protocols.Signature{Type: protocols.CKG}.String(), cpk)
	if err != nil {
		panic(fmt.Errorf("%s | CPK was not found for node %s: %s", a.sess.NodeID, a.sess.NodeID, err))
	}
	encryptor := bfv.NewEncryptor(bfvParams, cpk)

	// craft input
	var inData [8]uint64
	val, err := strconv.Atoi(strings.Split(string(a.node.ID()), "-")[1])
	if err != nil {
		panic(err)
	}
	for i := 0; i <= val; i++ {
		inData[i] = 1
	}
	inPt := encoder.EncodeNew(inData[:], bfvParams.MaxLevel())
	inCt := encryptor.EncryptNew(inPt)

	// "//nodeID//circuitID/inputID"
	opLabel := pkg.OperandLabel(fmt.Sprintf("//%s/%s/in-0", a.node.ID(), cLabel))
	ops = append(ops, pkg.Operand{OperandLabel: opLabel, Ciphertext: inCt})

	return ops
}

func (a *App) getClientOperandsPIR(bfvParams bfv.Parameters, encoder bfv.Encoder, cLabel pkg.CircuitID) []pkg.Operand {
	ops := []pkg.Operand{}
	cpk := new(rlwe.PublicKey)
	err := a.sess.ObjectStore.Load(protocols.Signature{Type: protocols.CKG}.String(), cpk)
	if err != nil {
		panic(fmt.Errorf("%s | CPK was not found for node %s: %s", a.sess.NodeID, a.sess.NodeID, err))
	}
	encryptor := bfv.NewEncryptor(bfvParams, cpk)
	inData := make([]uint64, bfvParams.N())
	// craft input

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
		"psi-2": func(ec compute.EvaluationContext) error {
			opIn1 := ec.Input("//node-0/in-0")
			opIn2 := ec.Input("//node-1/in-0")

			// ev := ec.ShallowCopy()
			res := ec.MulNew(opIn1.Ciphertext, opIn2.Ciphertext)
			ec.Relinearize(res, res)
			opRes := pkg.Operand{OperandLabel: "//cloud/out-0", Ciphertext: res}

			params := ec.Parameters().Parameters
			opOut, err := ec.CKS("DEC-0", opRes, map[string]string{
				"target":     "node-0",
				"aggregator": "cloud",
				"lvl":        strconv.Itoa(params.MaxLevel()),
				"smudging":   "1.0",
			})
			if err != nil {
				return err
			}

			ec.Output(opOut, "node-0")
			return nil
		},

		"pir-3": func(ec compute.EvaluationContext) error {

			// number of clients
			N := 3

			params := ec.Parameters()

			inops := make(chan struct {
				i    int
				op   pkg.Operand
				mask *bfv.PlaintextMul
			}, N)

			reqOpChan := make(chan pkg.Operand, 1)

			inWorkers := &sync.WaitGroup{}
			inWorkers.Add(N)
			for i := 0; i < N; i++ {
				// each input is provided by a goroutine
				go func(i int) {
					encoder := bfv.NewEncoder(params)
					maskCoeffs := make([]uint64, params.N())
					maskCoeffs[i] = 1
					mask := encoder.EncodeMulNew(maskCoeffs, params.MaxLevel())

					opIn := ec.Input(pkg.OperandLabel(fmt.Sprintf("//node-%d/in-0", i)))

					if i != 0 {
						inops <- struct {
							i    int
							op   pkg.Operand
							mask *bfv.PlaintextMul
						}{i, opIn, mask}
					} else {
						reqOpChan <- opIn
					}
					inWorkers.Done()
				}(i)
			}

			// close input channel when all input operands have been provided
			go func() {
				inWorkers.Wait()
				close(inops)
			}()

			// wait for the query ciphertext to be generated
			reqOp := <-reqOpChan

			// each received input operand can be processed by one of the NGoRoutine
			NGoRoutine := 8
			maskedOps := make(chan pkg.Operand, N)
			maskWorkers := &sync.WaitGroup{}
			maskWorkers.Add(NGoRoutine)
			for i := 0; i < NGoRoutine; i++ {
				go func() {
					evaluator := ec.ShallowCopy() // creates a shallow evaluator copy for this goroutine
					tmp := bfv.NewCiphertext(ec.Parameters(), 1, ec.Parameters().MaxLevel())
					for op := range inops {
						// 1) Multiplication of the query with the plaintext mask
						evaluator.Mul(reqOp.Ciphertext, op.mask, tmp)

						// 2) Inner sum (populate all the slots with the sum of all the slots)
						evaluator.InnerSum(tmp, tmp)

						// 3) Multiplication of 2) with the i-th ciphertext stored in the cloud
						maskedCt := evaluator.MulNew(tmp, op.op.Ciphertext)
						maskedOps <- pkg.Operand{Ciphertext: maskedCt}
					}
					maskWorkers.Done()
				}()
			}

			// close input processing channel when all input have been processed
			go func() {
				maskWorkers.Wait()
				close(maskedOps)
			}()

			evaluator := ec.ShallowCopy()
			tmpAdd := bfv.NewCiphertext(ec.Parameters(), 2, ec.Parameters().MaxLevel())
			c := 0
			for maskedOp := range maskedOps {
				evaluator.Add(maskedOp.Ciphertext, tmpAdd, tmpAdd)
				c++
			}

			res := evaluator.RelinearizeNew(tmpAdd)
			// output encrypted under CPK
			opRes := pkg.Operand{OperandLabel: "//cloud/out-0", Ciphertext: res}

			opOut, err := ec.CKS("DEC-0", opRes, map[string]string{
				"target":     "node-0",
				"aggregator": "cloud",
				"lvl":        strconv.Itoa(params.MaxLevel()),
				"smudging":   "1.0",
			})
			if err != nil {
				return err
			}

			// output encrypted under node-a public key
			ec.Output(opOut, "node-0")
			return nil
		},
	}
	for label, cDef := range testCircuits {
		if err := compute.RegisterCircuit(label, cDef); err != nil {
			panic(err)
		}
	}
}

// outputStats outputs the total network usage and time take to execute a protocol phase.
func (a *App) outputStats(phase string, elapsed time.Duration) {
	log.Println("==============", phase, "phase ==============")
	log.Printf("%s | finished setup for N=%d T=%d", a.nc.ID, len(a.nl), a.nc.SessionParameters[0].T)
	log.Printf("%s | execute returned after %s", a.nc.ID, elapsed)
	log.Printf("%s | network stats: %s\n", a.nc.ID, a.node.GetTransport().GetNetworkStats())

	if *outputMetrics {
		var statsJSON []byte
		statsJSON, err := json.MarshalIndent(map[string]string{
			"N":        fmt.Sprint(len(a.nl)),
			"T":        fmt.Sprint(a.nc.SessionParameters[0].T),
			"Wall":     fmt.Sprint(elapsed),
			"NetStats": a.node.GetTransport().GetNetworkStats().String(),
		}, "", "\t")
		if err != nil {
			panic(err)
		}
		if errWrite := os.WriteFile(fmt.Sprintf("/helium/stats/%s.json", a.nc.ID), statsJSON, 0600); errWrite != nil {
			log.Println(errWrite)
		}
	}
}
