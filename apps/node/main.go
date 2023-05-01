package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/ldsec/helium/pkg/utils"

	"github.com/ldsec/helium/pkg/node"
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

	// TODO assumes single-session nodes
	if len(nc.SessionParameters) != 1 {
		panic("multi-session nodes not implemented")
	}

	if errConn := node.Connect(); errConn != nil {
		panic(errConn)
	}

	start := time.Now()
	err = node.GetSetupService().Execute(sd, nl)
	if err != nil {
		log.Printf("Node %s | execute returned an error: %s", nc.ID, err)
	}
	elapsed := time.Since(start)
	log.Printf("%s | finished setup for N=%d T=%d", nc.ID, len(nl), nc.SessionParameters[0].T)
	log.Printf("%s | execute returned after %s", nc.ID, elapsed)
	log.Printf("%s | network stats: %s", nc.ID, node.GetTransport().GetNetworkStats())

	if *outputMetrics {
		var statsJSON []byte
		statsJSON, err = json.MarshalIndent(map[string]string{
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
	} else {
		log.Printf("Node %s | metrics disabled, skipping writing to disk", nc.ID)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	log.Printf("Node %s | exiting.", nc.ID)
}
