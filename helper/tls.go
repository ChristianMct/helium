package helper

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ChristianMct/helium"
	"google.golang.org/grpc/credentials"
)

// validNodeID returns an error if id is not a valid DNS hostname. The
// helper-assisted setting always uses node ids as the host part of operand ids
// (see helium.OperandID), and, when mTLS is enabled, as TLS server names and as
// the dNSName SAN of the node certificates (see TLSConfig): both restrict node ids
// to lowercase DNS names. This check is therefore run unconditionally, even with
// TLSConfig.InsecureChannels.
func validNodeID(id helium.NodeID) error {
	if len(id) == 0 {
		return fmt.Errorf("node id is empty")
	}
	if len(id) > 253 {
		return fmt.Errorf("node id %q is too long: %d characters, max 253", id, len(id))
	}
	for _, label := range strings.Split(string(id), ".") {
		if len(label) == 0 || len(label) > 63 {
			return fmt.Errorf("node id %q has an empty or over-long (>63) label", id)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("node id %q has a label starting or ending with a hyphen", id)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			isLower := c >= 'a' && c <= 'z'
			isDigit := c >= '0' && c <= '9'
			if !isLower && !isDigit && c != '-' {
				return fmt.Errorf("node id %q contains invalid character %q: node ids must be lowercase DNS names", id, c)
			}
		}
	}
	return nil
}

// material holds the TLS material of a node, as resolved from the config: the
// node's own certificate and key, and the pool of the issuing authority.
type material struct {
	own tls.Certificate
	ca  *x509.CertPool
}

// load resolves the node's TLS material. The PEM-encoded fields of the config take
// precedence; the fields left empty are read from FromDirectory, when set.
func (c TLSConfig) load(self helium.NodeID) (*material, error) {
	caPEM, certPEM, keyPEM := c.CACert, c.OwnCert, c.OwnKey

	if c.FromDirectory != "" {
		read := func(dst *string, filename string) error {
			if *dst != "" {
				return nil
			}
			b, err := os.ReadFile(filepath.Join(c.FromDirectory, filename))
			if err != nil {
				return fmt.Errorf("could not read %s: %w", filename, err)
			}
			*dst = string(b)
			return nil
		}
		if err := read(&caPEM, "ca.crt"); err != nil {
			return nil, err
		}
		if err := read(&certPEM, fmt.Sprintf("%s.crt", self)); err != nil {
			return nil, err
		}
		if err := read(&keyPEM, fmt.Sprintf("%s.key", self)); err != nil {
			return nil, err
		}
	}

	switch {
	case caPEM == "":
		return nil, fmt.Errorf("no CA certificate: set CACert or FromDirectory")
	case certPEM == "":
		return nil, fmt.Errorf("no certificate for node %s: set OwnCert or FromDirectory", self)
	case keyPEM == "":
		return nil, fmt.Errorf("no private key for node %s: set OwnKey or FromDirectory", self)
	}

	own, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("invalid certificate/key pair for node %s: %w", self, err)
	}

	ca := x509.NewCertPool()
	if !ca.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, fmt.Errorf("could not parse any certificate from the CA certificate")
	}

	return &material{own: own, ca: ca}, nil
}

// validate checks that the TLS material resolves and that the node's own
// certificate carries its node id as a dNSName SAN. It is called at config
// validation time so that a misprovisioned node fails to start, rather than
// failing on its first handshake.
func (c TLSConfig) validate(self helium.NodeID) error {
	if c.InsecureChannels {
		return nil
	}

	mat, err := c.load(self)
	if err != nil {
		return err
	}

	leaf, err := x509.ParseCertificate(mat.own.Certificate[0])
	if err != nil {
		return fmt.Errorf("could not parse the node's own certificate: %w", err)
	}
	if !slices.Contains(leaf.DNSNames, string(self)) {
		return fmt.Errorf("the certificate of node %s does not carry %s as a dNSName SAN (has %v)", self, self, leaf.DNSNames)
	}
	return nil
}

// serverCredentials returns the transport credentials of the helper server. Client
// certificates are required and verified against the CA: this is what populates the
// verified chain that authenticatedNodeID reads the caller's identity from.
func (c TLSConfig) serverCredentials(self helium.NodeID) (credentials.TransportCredentials, error) {
	mat, err := c.load(self)
	if err != nil {
		return nil, err
	}
	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{mat.own},
		ClientCAs:    mat.ca,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}), nil
}

// clientCredentials returns the transport credentials of a peer node dialing the
// helper. ServerName is set to the helper's node id rather than being derived from
// the dialed address: the helper's address in the node list may be an IP or a
// container name, and it is the node id that must be authenticated.
func (c TLSConfig) clientCredentials(self, helperID helium.NodeID) (credentials.TransportCredentials, error) {
	mat, err := c.load(self)
	if err != nil {
		return nil, err
	}
	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{mat.own},
		RootCAs:      mat.ca,
		ServerName:   string(helperID),
		MinVersion:   tls.VersionTLS13,
	}), nil
}
