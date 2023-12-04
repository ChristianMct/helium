package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ldsec/helium/pkg/circuits"
	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v4/bgv"
	"github.com/tuneinsight/lattigo/v4/rlwe"

	"github.com/ldsec/helium/pkg/node"
	"github.com/ldsec/helium/pkg/services/compute"
)

const DefaultAddress = ""

var (
	addr             = flag.String("address", DefaultAddress, "the address on which the node will listen")
	configFile       = flag.String("config", "/helium/config/node.json", "the node config file for this node")
	nodeList         = flag.String("nodes", "/helium/config/nodelist.json", "the node list file")
	insecureChannels = flag.Bool("insecureChannels", false, "run the MPC over unauthenticated channels")
	tlsdir           = flag.String("tlsdir", "", "a directory with the required TLS cryptographic material")
	expDuration      = flag.Duration("expDuration", 10*time.Second, "the duration of the experiment, see time.ParseDuration for valid input formats.")
	// outputMetrics    = flag.Bool("outputMetrics", false, "outputs metrics to a file")
	// docompute        = flag.Bool("docompute", true, "executes the compute phase")
	// setupFile        = flag.String("setup", "/helium/config/setup.json", "the setup description file")
	// computeFile      = flag.String("compute", "/helium/config/compute.json", "the compute description file")
	// keepRunning      = flag.Bool("keepRunning", false, "keeps the node running until system SIGINT or SIGTERM")
)

type Config struct {
	nc node.Config
	nl pkg.NodesList
	// sd setup.Description
	// cd compute.Description
}

// main is the entrypoint of the node application.
// Instructions to run: go run main.go node.go -config [nodeconfigfile].
func main() {

	flag.Parse()

	conf := Config{}

	var err error
	if err = utils.UnmarshalFromFile(*configFile, &conf.nc); err != nil {
		log.Println("could not read config:", err)
		os.Exit(1)
	}

	if *addr != DefaultAddress || conf.nc.Address == "" {
		// CLI addr overrides config address
		conf.nc.Address = pkg.NodeAddress(*addr)
	}

	if *insecureChannels {
		conf.nc.TLSConfig.InsecureChannels = *insecureChannels
	}

	if *tlsdir != "" {
		conf.nc.TLSConfig.FromDirectory = *tlsdir
	}

	// TODO assumes single-session nodes
	if len(conf.nc.SessionParameters) != 1 {
		panic("multi-session nodes not implemented")
	}

	if err = utils.UnmarshalFromFile(*nodeList, &conf.nl); err != nil {
		log.Println("could not read nodelist:", err)
		os.Exit(1)
	}

	fmt.Printf("%+v\n", conf.nc)
	conf.nc.SessionParameters[0].RLWEParams.NTTFlag = true
	rlweParams, err := rlwe.NewParametersFromLiteral(conf.nc.SessionParameters[0].RLWEParams)
	if err != nil {
		panic(err)
	}
	params, err := bgv.NewParameters(rlweParams, 65537)
	if err != nil {
		panic(err)
	}

	nParty := len(conf.nc.SessionParameters[0].Nodes)

	encoder := bgv.NewEncoder(params) // TODO pass encoder in ip ?

	app := node.App{
		Circuits: map[string]compute.Circuit{
			"mul4-dec": mul4Dec,
		},
		InputProvider: getInputProvider(conf.nc.ID, nParty, params, encoder),
	}

	node, err := node.NewNode(conf.nc, conf.nl)
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

	err = node.Connect()
	if err != nil {
		panic(err)
	}

	sessId := pkg.SessionID("test-session")
	ctx := pkg.NewContext(&sessId, nil)

	sigs, outs, err := node.Run(ctx, app)
	if err != nil {
		panic(err)
	}

	start := time.Now()
	var nSig int
	if conf.nc.ID == "cloud" {
		go func() {
			for i := 0; time.Since(start) < *expDuration; i++ {
				sigs <- circuits.Signature{CircuitName: "mul4-dec", CircuitID: pkg.CircuitID(fmt.Sprintf("test-circuit-%d", i))}
				nSig++
			}
			close(sigs)
		}()
	}

	var nRes int
	for out := range outs {
		res := make([]uint64, params.PlaintextSlots())
		encoder.Decode(out.Pt, res)
		res = res[:nParty]
		checkResultCorrect(out.OperandLabel, res)
		node.Logf("got correct result for %s: %v", out.OperandLabel, res)
		nRes++
	}

	if conf.nc.ID == "cloud" {
		node.Logf("Processed %d/%d signatures in %s", nSig, nRes, time.Since(start))
	}
	node.Logf("exiting.")
}

func getInputProvider(nodeId pkg.NodeID, nParty int, params bgv.Parameters, encoder *bgv.Encoder) *compute.InputProvider {

	ip := func(ctx context.Context, ol pkg.OperandLabel) (*rlwe.Plaintext, error) {
		encoder := encoder.ShallowCopy()
		url, err := pkg.ParseURL(string(ol))
		if err != nil {
			return nil, err
		}

		if url.NodeID() == "cloud" {
			return nil, nil
		}

		nodeNum, err := strconv.Atoi(strings.TrimPrefix(string(nodeId), "node-"))
		if err != nil {
			panic(err)
		}

		val, err := strconv.Atoi(strings.TrimPrefix(string(url.CircuitID()), "test-circuit-"))
		if err != nil {
			return nil, err
		}

		var pt *rlwe.Plaintext
		data := make([]uint64, nParty, nParty)
		for i := range data {
			if i == nodeNum {
				data[i] = uint64(val)
			} else {
				data[i] = 1
			}
		}

		pt = bgv.NewPlaintext(params, params.MaxLevelQ())
		err = encoder.Encode(data, pt)

		if err != nil {
			return nil, err
		}
		return pt, nil
	}
	return (*compute.InputProvider)(&ip)
}

func mul4Dec(e compute.EvaluationContext) error {

	inputs := make(chan pkg.Operand, 4)
	inOpls := utils.NewSet([]pkg.OperandLabel{"//node-0/in-0", "//node-1/in-0", "//node-2/in-0", "//node-3/in-0"})
	for inOpl := range inOpls {
		inOpl := inOpl
		go func() {
			inputs <- e.Input(inOpl)
		}()
	}

	op0 := <-inputs
	op1 := <-inputs

	lvl2 := make(chan *rlwe.Ciphertext, 2)
	go func() {
		ev := e.NewEvaluator()
		res, _ := ev.MulNew(op0.Ciphertext, op1.Ciphertext)
		ev.Relinearize(res, res)
		lvl2 <- res
	}()

	op2 := <-inputs
	op3 := <-inputs

	go func() {
		ev := e.NewEvaluator()
		res, _ := ev.MulNew(op2.Ciphertext, op3.Ciphertext)
		ev.Relinearize(res, res)
		lvl2 <- res
	}()

	res1, res2 := <-lvl2, <-lvl2
	res, _ := e.MulNew(res1, res2)
	e.Relinearize(res, res)

	params := e.Parameters().Parameters
	opres := pkg.Operand{OperandLabel: "//cloud/res-0", Ciphertext: res}
	opout, err := e.DEC(opres, map[string]string{
		"target":   "cloud",
		"lvl":      strconv.Itoa(params.MaxLevel()),
		"smudging": "1.0",
	})
	if err != nil {
		return err
	}

	e.Output(opout, "cloud")

	return nil
}

func checkResultCorrect(opl pkg.OperandLabel, res []uint64) {
	url, err := pkg.ParseURL(string(opl))
	if err != nil {
		panic(err)
	}
	val, err := strconv.Atoi(strings.TrimPrefix(string(url.CircuitID()), "test-circuit-"))
	if err != nil {
		panic(err)
	}

	for _, v := range res {
		if v != uint64(val) {
			panic(fmt.Errorf("incorrect result for %s: %v", opl, res))
		}
	}
}
