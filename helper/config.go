package helper

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ChristianMct/helium"
)

// Config is the configuration of a node in the helper-assisted setting. It extends
// the node configuration with the helper's identity and the setting-specific knobs.
// The struct is meant to be encoded and decoded to JSON with the standard library's
// encoding/json package.
type Config struct {
	helium.Config

	// HelperID is the node id of the helper node.
	Helper helium.NodeInfo

	// MaxProtoPerNode is the maximum number of protocols a node is selected as
	// participant for, at any given time (helper only). Zero means no limit.
	MaxProtoPerNode int

	TLS TLSConfig
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
func ValidateConfig(config Config) error {
	if len(config.ID) == 0 {
		return fmt.Errorf("config must specify a node ID")
	}
	if err := validNodeID(config.ID); err != nil {
		return fmt.Errorf("invalid node id: %w", err)
	}
	if len(config.Helper.NodeID) == 0 {
		return fmt.Errorf("config must specify a helper ID")
	}
	if err := validNodeID(config.Helper.NodeID); err != nil {
		return fmt.Errorf("invalid helper id: %w", err)
	}
	if len(config.Helper.NodeAddress) == 0 {
		return fmt.Errorf("config must specify a helper address")
	}
	// validate the session parameters.   TODO: should be a separated function.
	if len(config.SessionParameters.ID) == 0 {
		return fmt.Errorf("config must specify the session parameters")
	}
	if len(config.SessionParameters.Nodes) == 0 {
		return fmt.Errorf("node list is empty or nil")
	}
	for _, nid := range config.SessionParameters.Nodes {
		if err := validNodeID(nid); err != nil {
			return fmt.Errorf("invalid node id in the node list: %w", err)
		}
	}
	if err := config.TLS.validate(config.ID); err != nil {
		return fmt.Errorf("invalid TLS config: %w", err)
	}
	return nil
}

// TLSConfig configures the mutual TLS authentication between the helper and its
// peers. All nodes present a certificate issued by a common certificate authority,
// and a node's certificate must carry its node id as a dNSName SAN: the helper
// derives the caller's node id from the verified client certificate, and the peers
// authenticate the helper by its node id (see helium.NodeID).
type TLSConfig struct {
	// InsecureChannels disables TLS altogether. The sender's identity then falls
	// back to a self-asserted metadata header, so any node can impersonate any
	// other: FOR TESTING ONLY.
	InsecureChannels bool

	// FromDirectory is the path to a directory holding the TLS material as PEM files:
	// ca.crt, <node-id>.crt and <node-id>.key. It is only read for the fields left
	// empty below.
	FromDirectory string

	// CACert is the PEM-encoded certificate of the authority that issued all the
	// node certificates.
	CACert string
	// OwnCert is the node's own PEM-encoded certificate.
	OwnCert string
	// OwnKey is the node's own PEM-encoded private key.
	OwnKey string
}
