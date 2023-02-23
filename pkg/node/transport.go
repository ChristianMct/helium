package node

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha1" //nolint:gosec // sha1 needed to check certificate
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	pkg "github.com/ldsec/helium/pkg/session"
	cryptoUtil "github.com/ldsec/helium/pkg/utils/crypto"
)

type TLSConfig struct {
	InsecureChannels bool // Are we running with TLS disabled?
	FromDirectory    string
	PeerPKs          map[pkg.NodeID]string // Mapping of <node, pubKey> where pubKey is PEM encoded
	PeerCerts        map[pkg.NodeID]string // Mapping of <node, certifcate> where pubKey is PEM encoded ASN.1 DER file
	CACert           string                // Root CA certificate - needed to validate the certificate chain
	OwnCert          string
	OwnPk            string
	OwnSk            string
}

type tlsSetup struct {
	withInsecureChannels bool
	peerPKs              map[pkg.NodeID]crypto.PublicKey  // keep track of the public keys used by peers.
	peerCerts            map[pkg.NodeID]*x509.Certificate // keep track of certificates used by peers.
	ownCert              *x509.Certificate
	ownPk                crypto.PublicKey
	ownSk                crypto.PrivateKey
	caCert               *x509.Certificate
}

// IsValid checks if the TLSConfig is valid - as in all fields are initialised with proper values
func (tls tlsSetup) IsValid() bool {
	return tls.withInsecureChannels || (tls.peerPKs != nil && tls.peerCerts != nil && len(tls.peerPKs) == len(tls.peerCerts) &&
		tls.ownCert.Raw != nil && tls.caCert.Raw != nil && tls.ownSk != nil && tls.ownPk != nil)
}

// IsSelfContained checks if the given TLSSpec contains all the needed information to directly bootstrap a functional
// TLSConfig. Requires to know the number of peers a node has.
func (spec *TLSConfig) IsSelfContained(totalPeers int) bool {
	if spec.CACert == "" {
		return false
	}
	if len(spec.PeerCerts) != totalPeers || len(spec.PeerPKs) != totalPeers {
		return false
	}
	return true
}

// getTLSSetup will evaluate the given spec and based on it determine how to seed
// the cryptographic material needed by a node. The following strategies are supported
// and will be tried in subsequent order
//   - Config: if the tls config already contains all the info we need (static public/private keys and certs), use those
//   - Filesystem: if a directory path is provided, attempted to load the cryptographic material from the directory if it is missing from the config
func (node *Node) getTLSSetup(config TLSConfig) (setup *tlsSetup, err error) {

	setup = new(tlsSetup)
	setup.withInsecureChannels = config.InsecureChannels

	if config.InsecureChannels {
		return &tlsSetup{withInsecureChannels: true}, nil
	}

	if config.FromDirectory != "" { // TODO: tests for this path
		loadStringFromDirFile := func(id pkg.NodeID, filename string) (string, error) {
			b, err := os.ReadFile(filepath.Join(config.FromDirectory, fmt.Sprintf(filename, id)))
			return string(b), err
		}

		if config.OwnSk == "" {
			config.OwnSk, err = loadStringFromDirFile(node.id, "%s.key")
			if err != nil {
				return nil, fmt.Errorf("could not load secret key from file: %s", err)
			}
		}
		if config.OwnPk == "" {
			config.OwnPk, err = loadStringFromDirFile(node.id, "%s_pub.key")
			if err != nil {
				return nil, fmt.Errorf("could not load public key from file: %s", err)
			}
		}
		if config.OwnCert == "" {
			config.OwnCert, err = loadStringFromDirFile(node.id, "%s.crt")
			if err != nil {
				return nil, fmt.Errorf("could not certificate from file: %s", err)
			}
		}

		if len(config.PeerPKs) == 0 {
			for _, peer := range node.peers {
				config.PeerPKs[peer.id], err = loadStringFromDirFile(peer.id, "%s_pub.key")
				if err != nil {
					return nil, fmt.Errorf("could not load peer %s public key from file: %s", peer.id, err)
				}
			}
		}

		if len(config.PeerCerts) == 0 {
			for _, peer := range node.peers {
				config.PeerCerts[peer.id], err = loadStringFromDirFile(peer.id, "%s.crt")
				if err != nil {
					return nil, fmt.Errorf("could not load peer %s certificate from file: %s", peer.id, err)
				}
			}
		}

	}

	setup.ownSk, err = cryptoUtil.ParseSk([]byte(config.OwnSk))
	if err != nil {
		return nil, err
	}

	setup.ownPk, err = cryptoUtil.ParsePk([]byte(config.OwnPk))
	if err != nil {
		return nil, err
	}

	setup.ownCert, err = cryptoUtil.ParseCert([]byte(config.OwnCert))
	if err != nil {
		return nil, err
	}

	setup.caCert, err = cryptoUtil.ParseCert([]byte(config.CACert))
	if err != nil {
		return nil, err
	}

	setup.peerCerts, setup.peerPKs = make(map[pkg.NodeID]*x509.Certificate), make(map[pkg.NodeID]crypto.PublicKey)
	for peer := range node.peers {
		pkBytes, hasPk := config.PeerPKs[peer]
		if !hasPk {
			return nil, fmt.Errorf("missing public key for peer %s", peer)
		}
		setup.peerPKs[peer], err = cryptoUtil.ParsePk([]byte(pkBytes))
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key for peer %s: %s", peer, err)
		}

		certBytes, hasCert := config.PeerCerts[peer]
		if !hasCert {
			return nil, fmt.Errorf("missing certificate for peer %s", peer)
		}
		setup.peerCerts[peer], err = cryptoUtil.ParseCert([]byte(certBytes))
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate for peer %s: %s", peer, err)
		}
	}

	return setup, nil
}

// VfyPeerCerts demonstrates how to perform custom validation over the certificate offered by a peer while establishing
// a (m)TLS handshake.
// If normal verification is disabled by setting InsecureSkipVerify, or (for a server) when ClientAuth is
// RequestClientCert / RequireAnyClientCert, then this callback will be considered but the verifiedChains argument
// will always be nil.
// This example uses the node's state to check if the identity of the certificate (given by commonName) matches one of its known peers.
func (node *Node) VfyPeerCerts(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	for _, rawCert := range rawCerts {
		c, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return err
		}

		_, ok := node.peers[pkg.NodeID(c.Subject.CommonName)]
		if ok {
			return nil
		}
	}
	return fmt.Errorf("no certificate offered contains peer identity")
}

// VfyConn demonstrates how to perform custom verification over the (m)TLS connection level. This callback is
// invoked after VerifyPeerCertificate
// Here I am using it a bit artificially to check the SKID field of a certificate and make sure it matches the public
// key we know of that peer.
// good sanity check - not much of a security benefit in doing it though.
func (node *Node) VfyConn(state tls.ConnectionState) error {
	skid := state.PeerCertificates[0].SubjectKeyId

	peerPk := node.tlsSetup.peerPKs[pkg.NodeID(state.PeerCertificates[0].Subject.CommonName)]
	switch peer := peerPk.(type) {
	case ed25519.PublicKey:
		peerHash := sha1.Sum(peer) //nolint:gosec // the cert uses sha1 so ignore the deprecation
		for i := range peerHash {
			if skid[i] != peerHash[i] {
				return fmt.Errorf("skid - invalid hash")
			}
		}
		return nil
	default:
	}
	return nil
}
