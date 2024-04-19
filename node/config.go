package node

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ChristianMct/helium/objectstore"
	"github.com/ChristianMct/helium/services/compute"
	"github.com/ChristianMct/helium/services/setup"
	"github.com/ChristianMct/helium/sessions"
)

// Config is the configuration of a node.
// The struct is meant to be encoded and decoded to JSON with the
// standard library's encoding/json package.
//
// In the current implementation, only a single session per node is supported.
type Config struct {
	ID                sessions.NodeID
	Address           Address
	HelperID          sessions.NodeID
	SessionParameters []sessions.Parameters
	SetupConfig       setup.ServiceConfig
	ComputeConfig     compute.ServiceConfig
	ObjectStoreConfig objectstore.Config
	TLSConfig         TLSConfig
}

// Address is the network address of a node.
type Address string

// Info contains the unique identifier and the network address of a node.
type Info struct {
	sessions.NodeID
	Address
}

// List is a list of known nodes in the network. It must contains all nodes
// for a given application, including the current node. It does not need to contain
// an address for all nodes, except for the helper node.
type List []Info

// AddressOf returns the network address of the node with the given ID. Returns
// an empty string if the node is not found in the list.
func (nl List) AddressOf(id sessions.NodeID) Address {
	for _, node := range nl {
		if node.NodeID == id {
			return node.Address
		}
	}
	return ""
}

// String returns a string representation of the list of nodes.
func (nl List) String() string {
	str := "[ "
	for _, node := range nl {
		str += fmt.Sprintf(`{ID: %s, Address: %s} `,
			node.NodeID, node.Address)
	}
	return str + "]"
}

// String returns a string representation of the node address.
func (na Address) String() string {
	return string(na)
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
func ValidateConfig(config Config, nl List) error {
	if len(config.ID) == 0 {
		return fmt.Errorf("config must specify a node ID")
	}
	if len(config.HelperID) == 0 {
		return fmt.Errorf("config must specify a helper ID")
	}
	if len(nl) == 0 {
		return fmt.Errorf("node list is empty or nil")
	}
	if nl.AddressOf(config.HelperID) == "" {
		return fmt.Errorf("no address for helper node `%s` in the node list", config.HelperID)
	}
	return nil
}

// TLSConfig is a struct for specifying TLS-related configuration.
// TLS is not supported yet.
//
//nolint:gosec // sha1 needed to check certificate
type TLSConfig struct {
	InsecureChannels bool                       // if set, disables TLS authentication
	FromDirectory    string                     // path to a directory containing the TLS material as files
	PeerPKs          map[sessions.NodeID]string // Mapping of <node, pubKey> where pubKey is PEM encoded
	PeerCerts        map[sessions.NodeID]string // Mapping of <node, certifcate> where pubKey is PEM encoded ASN.1 DER string
	CACert           string                     // Root CA certificate as a PEM encoded ASN.1 DER string
	OwnCert          string                     // Own certificate as a PEM encoded ASN.1 DER string
	OwnPk            string                     // Own public key as a PEM encoded string
	OwnSk            string                     // Own secret key as a PEM encoded string
}
