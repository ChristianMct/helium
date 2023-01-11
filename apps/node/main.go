package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ldsec/helium/pkg/node"
	"github.com/ldsec/helium/pkg/services/manage"
	"github.com/ldsec/helium/pkg/services/setup"
	pkg "github.com/ldsec/helium/pkg/session"
)

const DefaultAddress = ":40000"

var addr = flag.String("address", DefaultAddress, "the address on which the node will listen")
var configFile = flag.String("config", "/helium/config/node.json", "the node config file for this node")
var nodeList = flag.String("nodes", "/helium/config/nodelist.json", "the node list file")
var setupFile = flag.String("setup", "/helium/config/setup.json", "the setup description file")

// Instructions to run: go run main.go node.go -config [nodeconfigfile].
func main() {

	flag.Parse()

	if *configFile == "" {
		log.Println("need to provide a config file with the -config flag")
		os.Exit(1)
	}

	var err error
	var nc node.Config
	if err = UnmarshalFromFile(*configFile, &nc); err != nil {
		log.Println("could not read config:", err)
		os.Exit(1)
	}

	if *addr != DefaultAddress || nc.Address == "" {
		nc.Address = pkg.NodeAddress(*addr)
	}

	if nc.ID == "" {
		log.Println("bad config: no ID")
		os.Exit(1)
	}

	var nl pkg.NodesList
	if err = UnmarshalFromFile(*nodeList, &nl); err != nil {
		log.Println("could not read nodelist:", err)
		os.Exit(1)
	}

	var sd setup.Description
	if *setupFile != "" {
		if err = UnmarshalFromFile(*setupFile, &sd); err != nil {
			log.Printf("could not read setup description file: %s\n", err)
			os.Exit(1)
		}
	}

	node, err := node.NewNode(nc, nl)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	log.Printf("Node %s | loading services:\n", nc.ID)
	manageService := manage.NewManageService(node)
	log.Println("\t- manage: OK")

	setupService, err := setup.NewSetupService(node)
	if err != nil {
		log.Println("\t- setup: ERROR")
		log.Println(err)
	}
	log.Println("\t- setup: OK")

	// TODO assumes single-session nodes
	if len(nc.SessionParameters) != 1 {
		panic("multi-session nodes implemented")
	}

	sessID := nc.SessionParameters[0].ID

	sess, exists := node.GetSessionFromID(sessID)
	if !exists {
		log.Fatalf("Node %s | session was not created\n", nc.ID)
	}

	if err = setupService.LoadSetupDescription(sess, sd); err != nil {
		log.Printf("could not read protocols map: %s\n", err)
		os.Exit(1)
	}

	log.Printf("Node %s | loaded the protocol map \n", nc.ID)

	lis, err := net.Listen("tcp", string(nc.Address))
	if err != nil {
		log.Printf("Node %s | failed to listen: %v\n", nc.ID, err)
	}

	go node.StartListening(lis)

	<-time.After(time.Second)

	err = node.Connect()
	if err != nil {
		log.Printf("Node %s | connection error: %s", nc.ID, err)
	}
	err = manageService.Connect()
	if err != nil {
		log.Printf("Node %s | manage service conn error: %s", nc.ID, err)
	}
	setupService.Connect()

	manageService.GreetAll()

	manageService.Greets.Wait()

	start := time.Now()
	err = setupService.Execute()
	if err != nil {
		log.Printf("Node %s | execute returned an error: %s", nc.ID, err)
	}
	elapsed := time.Since(start)
	log.Printf("Node %s | finished setup for N=%d T=%d", nc.ID, len(nl), nc.SessionParameters[0].T)
	log.Printf("Node %s | execute returned after %s", nc.ID, elapsed)
	log.Printf("Node %s | network stats: %s", nc.ID, node.GetNetworkStats())

	statsJSON, err := json.MarshalIndent(map[string]string{
		"N":        fmt.Sprint(len(nl)),
		"T":        fmt.Sprint(nc.SessionParameters[0].T),
		"Wall":     fmt.Sprint(elapsed),
		"NetStats": node.GetNetworkStats().String(),
	}, "", "\t")
	if err != nil {
		panic(err)
	}
	if errWrite := ioutil.WriteFile(fmt.Sprintf("/helium/stats/%s.json", nc.ID), statsJSON, 0600); errWrite != nil {
		log.Println(errWrite)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	log.Printf("Node %s | exiting.", nc.ID)
}

func UnmarshalFromFile(filename string, s interface{}) error {
	confFile, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("could not open file: %w", err)
	}

	cb, err := io.ReadAll(confFile)
	if err != nil {
		return fmt.Errorf("could not read file: %w", err)
	}

	err = json.Unmarshal(cb, s)
	if err != nil {
		return fmt.Errorf("could not parse the file: %w", err)
	}

	return nil
}
