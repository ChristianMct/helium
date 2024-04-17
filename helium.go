// Package helium provides the main types and interfaces for the Helium framework.
package helium

import (
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/ChristianMct/helium/session"
)

// NodeAddress is the network address of a node.
type NodeAddress string

// NodeInfo contains the unique identifier and the network address of a node.
type NodeInfo struct {
	session.NodeID
	NodeAddress
}

// NodesList is a list of known nodes in the network. It must contains all nodes
// for a given application, including the current node. It does not need to contain
// an address for all nodes, except for the helper node.
type NodesList []NodeInfo

// AddressOf returns the network address of the node with the given ID. Returns
// an empty string if the node is not found in the list.
func (nl NodesList) AddressOf(id session.NodeID) NodeAddress {
	for _, node := range nl {
		if node.NodeID == id {
			return node.NodeAddress
		}
	}
	return ""
}

// String returns a string representation of the list of nodes.
func (nl NodesList) String() string {
	str := "[ "
	for _, node := range nl {
		str += fmt.Sprintf(`{ID: %s, Address: %s} `,
			node.NodeID, node.NodeAddress)
	}
	return str + "]"
}

// String returns a string representation of the node address.
func (na NodeAddress) String() string {
	return string(na)
}

// URL defines a URL format to serve as ciphertext identifier for
// the Helium framwork.
type URL url.URL

// ParseURL parses a string into a helium URL.
func ParseURL(s string) (*URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	return (*URL)(u), nil
}

// NodeID returns the host part of the URL as a NodeID.
func (u *URL) NodeID() session.NodeID {
	return session.NodeID(u.Host)
}

func (u *URL) CiphertextBaseID() session.CiphertextID {
	return session.CiphertextID(path.Base(u.Path))
}

func (u *URL) CiphertextID() session.CiphertextID {
	return session.CiphertextID(u.String())
}

// CircuitID returns the circuit id part of the URL, if any.
// Returns the empty string if no circuit id is present.
func (u *URL) CircuitID() string {
	if dir, _ := path.Split(u.Path); len(dir) > 0 { // ctid belongs to a circuit
		return strings.SplitN(strings.Trim(dir, "/"), "/", 2)[0]
	}
	return ""
}

// String returns the string representation of the URL.
func (u *URL) String() string {
	return (*url.URL)(u).String()
}

// TLSConfig is a struct for specifying TLS-related configuration.
// TLS is not supported yet.
//
//nolint:gosec // sha1 needed to check certificate
type TLSConfig struct {
	InsecureChannels bool                      // if set, disables TLS authentication
	FromDirectory    string                    // path to a directory containing the TLS material as files
	PeerPKs          map[session.NodeID]string // Mapping of <node, pubKey> where pubKey is PEM encoded
	PeerCerts        map[session.NodeID]string // Mapping of <node, certifcate> where pubKey is PEM encoded ASN.1 DER string
	CACert           string                    // Root CA certificate as a PEM encoded ASN.1 DER string
	OwnCert          string                    // Own certificate as a PEM encoded ASN.1 DER string
	OwnPk            string                    // Own public key as a PEM encoded string
	OwnSk            string                    // Own secret key as a PEM encoded string
}
