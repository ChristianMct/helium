package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"

	"github.com/ldsec/helium/pkg/node"
	"github.com/ldsec/helium/pkg/services/manage"
	"github.com/ldsec/helium/pkg/services/setup"
	pkg "github.com/ldsec/helium/pkg/session"
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

	node, err := node.NewNode(nc)
	if err != nil {
		fmt.Println(err)
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

	if len(pm) > 0 {

		// TODO assumes single-session nodes

		if len(nc.SessionParameters) != 1 {
			panic("multi-session nodes implemented")
		}

		sessId := nc.SessionParameters[0].ID

		sess, exists := node.GetSessionFromID(pkg.SessionID(sessId))
		if !exists {
			log.Fatalf("Node %s | session was not created\n", nc.Address)
		}
		if err = setupService.LoadProtocolMap(sess, pm); err != nil {
			fmt.Printf("could not read protocols map: %s\n", err)
			os.Exit(1)
		}

		log.Printf("Node %s | loaded the protocol map \n", nc.ID)
	}

	lis, err := net.Listen("tcp", string(nc.Address))
	if err != nil {
		log.Printf("Node %s | failed to listen: %v\n", nc.Address, err)
	}

	go node.StartListening(lis)

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
