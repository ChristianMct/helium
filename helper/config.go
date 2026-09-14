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
	HelperID helium.NodeID
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
func ValidateConfig(config Config, nl helium.NodeList) error {
	if len(config.ID) == 0 {
		return fmt.Errorf("config must specify a node ID")
	}
	if len(config.HelperID) == 0 {
		return fmt.Errorf("config must specify a helper ID")
	}
	if len(config.SessionParameters.ID) == 0 {
		return fmt.Errorf("config must specify the session parameters")
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
	InsecureChannels bool                     // if set, disables TLS authentication
	FromDirectory    string                   // path to a directory containing the TLS material as files
	PeerPKs          map[helium.NodeID]string // Mapping of <node, pubKey> where pubKey is PEM encoded
	PeerCerts        map[helium.NodeID]string // Mapping of <node, certifcate> where pubKey is PEM encoded ASN.1 DER string
	CACert           string                   // Root CA certificate as a PEM encoded ASN.1 DER string
	OwnCert          string                   // Own certificate as a PEM encoded ASN.1 DER string
	OwnPk            string                   // Own public key as a PEM encoded string
	OwnSk            string                   // Own secret key as a PEM encoded string
}
