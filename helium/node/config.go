package node

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ldsec/helium/helium"
	"github.com/ldsec/helium/helium/objectstore"
	"github.com/ldsec/helium/helium/services/compute"
	"github.com/ldsec/helium/helium/services/setup"
	"github.com/ldsec/helium/helium/session"
	"github.com/ldsec/helium/helium/transport/centralized"
)

// Config is the configuration of a node.
// The struct is meant to be encoded and decoded to JSON with the
// standard library's encoding/json package.
//
// In the current implementation, only a single session per node is supported.
type Config struct {
	ID                helium.NodeID
	Address           helium.NodeAddress
	HelperID          helium.NodeID
	SessionParameters []session.Parameters
	SetupConfig       setup.ServiceConfig
	ComputeConfig     compute.ServiceConfig
	ObjectStoreConfig objectstore.Config
	TLSConfig         centralized.TLSConfig
}

// LoadConfigFromFile loads a node configuration from a JSON file.
func LoadConfigFromFile(filename string) (Config, error) {
	// Open the config file
	file, err := os.Open(filename)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()

	// Decode the config file into the config variable
	var config Config
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		return Config{}, err
	}

	return config, nil
}

// ValidateConfig checks that the configuration is valid.
func ValidateConfig(config Config, nl helium.NodesList) error {
	if len(config.ID) == 0 {
		return fmt.Errorf("config must specify a node ID")
	}
	if len(config.HelperID) == 0 {
		return fmt.Errorf("config must specify a helper ID")
	}
	if nl.AddressOf(config.HelperID) == "" {
		return fmt.Errorf("helper ID not found in the node list")
	}
	return nil
}
