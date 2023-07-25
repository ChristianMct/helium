package grpctrans

import (
	"crypto" //nolint:gosec // sha1 needed to check certificate
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ldsec/helium/pkg"
	cryptoUtil "github.com/ldsec/helium/pkg/utils/crypto"
)

// TLSConfig is a struct for specifying TLS-related configuration.
type TLSConfig struct {
	InsecureChannels bool                  // if set, disables TLS authentication
	FromDirectory    string                // path to a directory containing the TLS material as files
	PeerPKs          map[pkg.NodeID]string // Mapping of <node, pubKey> where pubKey is PEM encoded
	PeerCerts        map[pkg.NodeID]string // Mapping of <node, certifcate> where pubKey is PEM encoded ASN.1 DER string
	CACert           string                // Root CA certificate as a PEM encoded ASN.1 DER string
	OwnCert          string                // Own certificate as a PEM encoded ASN.1 DER string
	OwnPk            string                // Own public key as a PEM encoded string
	OwnSk            string                // Own secret key as a PEM encoded string
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
func (t *Transport) getTLSSetup(config TLSConfig) (setup *tlsSetup, err error) {

	setup = new(tlsSetup)
	setup.withInsecureChannels = config.InsecureChannels

	if config.InsecureChannels {
		return &tlsSetup{withInsecureChannels: true}, nil
	}

	if config.FromDirectory != "" { // TODO: tests for this path
		err = t.readConfigFromDir(&config)
		if err != nil {
			return nil, err
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
	for _, peer := range t.nodeList {

		if peer.NodeID == t.id {
			continue
		}

		pkBytes, hasPk := config.PeerPKs[peer.NodeID]
		if !hasPk {
			return nil, fmt.Errorf("missing public key for peer %s", peer.NodeID)
		}
		setup.peerPKs[peer.NodeID], err = cryptoUtil.ParsePk([]byte(pkBytes))
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key for peer %s: %w", peer.NodeID, err)
		}

		certBytes, hasCert := config.PeerCerts[peer.NodeID]
		if !hasCert {
			return nil, fmt.Errorf("missing certificate for peer %s", peer.NodeID)
		}
		setup.peerCerts[peer.NodeID], err = cryptoUtil.ParseCert([]byte(certBytes))
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate for peer %s: %w", peer.NodeID, err)
		}
	}

	return setup, nil
}

func (t *Transport) readConfigFromDir(config *TLSConfig) error {
	loadStringFromDirFile := func(id pkg.NodeID, filename string) (string, error) {
		b, errRead := os.ReadFile(filepath.Join(config.FromDirectory, fmt.Sprintf(filename, id)))
		return string(b), errRead
	}

	var err error
	errs := []error{}
	if config.OwnSk == "" {
		config.OwnSk, err = loadStringFromDirFile(t.id, "%s.key")
		errs = append(errs, fmt.Errorf("could not load secret key from file: %w", err))
	}
	if config.OwnPk == "" {
		config.OwnPk, err = loadStringFromDirFile(t.id, "%s_pub.key")
		errs = append(errs, fmt.Errorf("could not load public key from file: %w", err))
	}
	if config.OwnCert == "" {
		config.OwnCert, err = loadStringFromDirFile(t.id, "%s.crt")
		errs = append(errs, fmt.Errorf("could not load certificate from file: %w", err))
	}

	if len(config.PeerPKs) == 0 {
		for _, peer := range t.nodeList {
			config.PeerPKs[peer.NodeID], err = loadStringFromDirFile(peer.NodeID, "%s_pub.key")
			errs = append(errs, fmt.Errorf("could not load peer %s public key from file: %w", peer.NodeID, err))
		}
	}

	if len(config.PeerCerts) == 0 {
		for _, peer := range t.nodeList {
			config.PeerCerts[peer.NodeID], err = loadStringFromDirFile(peer.NodeID, "%s.crt")
			errs = append(errs, fmt.Errorf("could not load peer %s certificate from file: %w", peer.NodeID, err))
		}
	}
	return errors.Join(errs...)
}
