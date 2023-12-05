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
	"gonum.org/v1/gonum/mat"

	"github.com/ldsec/helium/pkg/node"
	"github.com/ldsec/helium/pkg/services/compute"
	"github.com/ldsec/helium/pkg/services/setup"
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
	//conf.nc.SessionParameters[0].RLWEParams.NTTFlag = true
	params, err := bgv.NewParametersFromLiteral(conf.nc.SessionParameters[0].RLWEParams)
	if err != nil {
		panic(err)
	}

	//nParty := len(conf.nc.SessionParameters[0].Nodes)

	m := params.PlaintextDimensions().Cols

	a := mat.NewDense(m, m, nil)
	a.Apply(func(i, j int, v float64) float64 {
		return float64(i) + float64(2*j)
	}, a)

	encoder := bgv.NewEncoder(params) // TODO pass encoder in ip ?

	var ip compute.InputProvider = func(ctx context.Context, ol pkg.OperandLabel) (*rlwe.Plaintext, error) {
		encoder := encoder.ShallowCopy()
		url, err := pkg.ParseURL(string(ol))
		if err != nil {
			return nil, err
		}

		if url.NodeID() == "cloud" {
			return nil, nil
		}

		nodeNum, err := strconv.Atoi(strings.TrimPrefix(string(conf.nc.ID), "node-"))
		if err != nil {
			panic(err)
		}

		// val, err := strconv.Atoi(strings.TrimPrefix(string(url.CircuitID()), "test-circuit-"))
		// if err != nil {
		// 	return nil, err
		// }

		var pt *rlwe.Plaintext
		b := mat.NewVecDense(m, nil)
		b.SetVec(nodeNum, 1)
		data := make([]uint64, len(b.RawVector().Data))
		for i, bi := range b.RawVector().Data {
			data[i] = uint64(bi)
		}

		pt = bgv.NewPlaintext(params, params.MaxLevelQ())
		err = encoder.Encode(data, pt)

		if err != nil {
			return nil, err
		}
		return pt, nil
	}

	checkResultCorrect := func(opl pkg.OperandLabel, res []uint64) {
		// url, err := pkg.ParseURL(string(opl))
		// if err != nil {
		// 	panic(err)
		// }
		// val, err := strconv.Atoi(strings.TrimPrefix(string(url.CircuitID()), "test-circuit-"))
		// if err != nil {
		// 	panic(err)
		// }

		b := mat.NewVecDense(m, nil)
		b.SetVec(0, 1)
		r := mat.NewVecDense(m, nil)

		r.MulVec(a, b)
		dataWant := make([]uint64, len(r.RawVector().Data))
		for i, v := range r.RawVector().Data {
			dataWant[i] = uint64(v)
		}

		for i, v := range res {
			if v != dataWant[i] {
				panic(fmt.Errorf("incorrect result for %s: \n has %v, want %v", opl, res, dataWant))
			}
		}
	}

	allNodes := make([]pkg.NodeID, len(conf.nl))
	for i := range conf.nl {
		allNodes[i] = conf.nl[i].NodeID
	}

	app := node.App{
		SetupDescription: &setup.Description{
			Cpk: allNodes,
		},
		Circuits: map[string]compute.Circuit{
			"matmul4-dec": matmul4dec,
		},
		InputProvider: &ip,
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

	node.Logf("connecting...")
	err = node.Connect()
	if err != nil {
		panic(err)
	}
	node.Logf("done")

	sessId := pkg.SessionID("test-session")
	ctx := pkg.NewContext(&sessId, nil)

	if conf.nc.ID == "cloud" {
		node.RegisterPostsetupHandler(func(ss *pkg.SessionStore, pkb compute.PublicKeyBackend) error {
			encoder := bgv.NewEncoder(params)

			cpk, err := pkb.GetCollectivePublicKey()
			if err != nil {
				return err
			}
			encryptor, err := bgv.NewEncryptor(params, cpk)
			if err != nil {
				return err
			}

			pta := make(map[int]*rlwe.Plaintext)
			cta := make(map[int]*rlwe.Ciphertext)
			sess, _ := ss.GetSessionFromID("test-session")

			diag := make(map[int][]uint64, m)
			for k := 0; k < m; k++ {
				diag[k] = make([]uint64, m)
				for i := 0; i < m; i++ {
					j := (i + k) % m
					diag[k][i] = uint64(a.At(i, j))
				}
			}

			node.Logf("generating encrypted matrix...")
			for di, d := range diag {
				pta[di] = rlwe.NewPlaintext(params, params.MaxLevel())
				encoder.Encode(d, pta[di])
				cta[di], err = encryptor.EncryptNew(pta[di])
				if err != nil {
					return err
				}
				sess.CiphertextStore.Store(pkg.Ciphertext{Ciphertext: *cta[di], CiphertextMetadata: pkg.CiphertextMetadata{ID: pkg.CiphertextID(fmt.Sprintf("//cloud/mat-diag-%d", di))}})
			}
			node.Logf("done")

			node.Logf("loading the evaluation keys...")
			for di := range diag {
				_, err = pkb.GetGaloisKey(params.GaloisElement(di))
				if err != nil {
					return err
				}
			}
			node.Logf("done")
			return nil
		})
	}

	sigs, outs, err := node.Run(ctx, app)
	if err != nil {
		panic(err)
	}

	node.WaitForSetupDone()

	start := time.Now()
	var nSig int
	if conf.nc.ID == "cloud" {
		go func() {
			for i := 0; time.Since(start) < *expDuration; i++ {
				sigs <- circuits.Signature{CircuitName: "matmul4-dec", CircuitID: pkg.CircuitID(fmt.Sprintf("test-circuit-%d", i))}
				nSig++
			}
			close(sigs)
		}()
	}

	var nRes int
	for out := range outs {
		res := make([]uint64, params.PlaintextSlots())
		encoder.Decode(out.Pt, res)
		res = res[:m]
		checkResultCorrect(out.OperandLabel, res)
		node.Logf("got correct result for %s", out.OperandLabel)
		nRes++
	}

	if conf.nc.ID == "cloud" {
		node.Logf("Processed %d/%d signatures in %s.", nSig, nRes, time.Since(start))
	}
	node.Logf("exiting.")
}

func matmul4dec(e compute.EvaluationContext) error {
	params := e.Parameters()

	m := params.PlaintextDimensions().Cols

	vecOp := e.Input(pkg.OperandLabel("//node-0/vec"))

	matOps := make(map[int]pkg.Operand)
	diagGalEl := make(map[int]uint64)
	for k := 0; k < m; k++ {
		matOps[k] = e.Load(pkg.OperandLabel(fmt.Sprintf("//cloud/mat-diag-%d", k)))
		diagGalEl[k] = params.GaloisElement(k)
	}

	if vecOp.Ciphertext == nil { //TODO: this is only for the circuit parser to pass...
		vecOp.Ciphertext = bgv.NewCiphertext(params, 1, params.MaxLevelQ())
	}

	vecDecom := e.NewDecompQPBuffer()
	vecRotated := bgv.NewCiphertext(params, 1, params.MaxLevelQ())
	e.DecomposeNTT(params.MaxLevelQ(), params.MaxLevelP(), params.PCount(), vecOp.Value[1], true, vecDecom)
	ctres := rlwe.NewCiphertext(params, 2, params.MaxLevel())
	for di, d := range matOps {
		if err := e.AutomorphismHoisted(vecOp.LevelQ(), vecOp.Ciphertext, vecDecom, diagGalEl[di], vecRotated); err != nil {
			return err
		}
		e.MulThenAdd(vecRotated, d.Ciphertext, ctres)
	}
	if err := e.Relinearize(ctres, ctres); err != nil {
		return err
	}

	opres := pkg.Operand{OperandLabel: "//cloud/res-0", Ciphertext: ctres}
	opout, err := e.DEC(opres, map[string]string{
		"target":   "cloud",
		"lvl":      strconv.Itoa(params.MaxLevel()),
		"smudging": fmt.Sprintf("%f", float64(1<<20)),
	})
	if err != nil {
		return err
	}

	e.Output(opout, "cloud")
	return nil
}
