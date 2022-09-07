package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"helium/pkg/node"
	"helium/pkg/services/manage"
	"helium/pkg/services/setup"
	pkg "helium/pkg/session"
	"io/ioutil"
	"log"
	"os"
	"time"
)

const DefaultAddress = ":40000"

var addr = flag.String("address", DefaultAddress, "the address on which the node will listen")
var configFile = flag.String("config", "./config/node.json", "the node config file for this node")
var protocolMapFile = flag.String("protocolmap", "", "the protocol map for the setup")

// Instructions to run: go run main.go node.go -config [nodeconfigfile]
func main() {

	flag.Parse()

	if *configFile == "" {
		fmt.Println("need to provide a config file with the -config flag")
		os.Exit(1)
	}

	var err error
	var nc node.NodeConfig
	if err = UnmarshalFromFile(*configFile, &nc); err != nil {
		fmt.Println("could not read config:", err)
		os.Exit(1)
	}

	if *addr != DefaultAddress || nc.Address == "" {
		nc.Address = pkg.NodeAddress(*addr)
	}

	if nc.ID == "" {
		fmt.Println("bad config: no ID")
		os.Exit(1)
	}

	var pm []setup.ProtocolDescriptor
	//var pm2 []string
	if *protocolMapFile != "" {
		if err = UnmarshalFromFile(*protocolMapFile, &pm); err != nil {
			fmt.Printf("could not read protocols map: %s\n", err)
			os.Exit(1)
		}
	}

	node := node.NewNode(nc)

	log.Printf("Node %s | loading services:\n", nc.ID)
	manageService := manage.NewManageService(node)
	log.Println("\t- manage: OK")

	setupService, err := setup.NewSetupService(node)
	if err != nil {
		log.Println("\t- setup: ERROR")
		log.Println(err)
	}
	log.Println("\t- setup: OK")

	if len(pm) > 0 {
		sess, exists := node.GetSessionFromID(pkg.SessionID(nc.SessionParameters.ID))
		if !exists {
			log.Fatalf("Node %s | session was not created\n", nc.Address)
		}
		if err = setupService.LoadProtocolMap(sess, pm); err != nil {
			fmt.Printf("could not read protocols map: %s\n", err)
			os.Exit(1)
		}

		log.Printf("Node %s | loaded the protocol map \n", nc.ID)
	}

	go node.StartListening()
	<-time.After(time.Second)

	node.Connect()
	manageService.Connect()
	setupService.Connect()

	manageService.GreetAll()

	manageService.Greets.Wait()

	err = setupService.Execute()
	if err != nil {
		log.Printf("Node %s | execute returned an error: %s", nc.Address, err)
	}

	<-time.After(1 * time.Second)
}

func UnmarshalFromFile(filename string, s interface{}) error {
	confFile, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("could not open file: %s", err)
	}

	cb, err := ioutil.ReadAll(confFile)
	if err != nil {
		return fmt.Errorf("could not read file: %s", err)
	}

	err = json.Unmarshal(cb, s)
	if err != nil {
		return fmt.Errorf("could not parse the file: %s", err)
	}

	return nil
}
