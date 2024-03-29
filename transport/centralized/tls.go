package centralized

import (
	//nolint:gosec // sha1 needed to check certificate

	"github.com/ChristianMct/helium"
)

// TLSConfig is a struct for specifying TLS-related configuration.
// TLS is not supported yet.
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
