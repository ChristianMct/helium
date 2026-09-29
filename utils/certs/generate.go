// Package certs generates the TLS material of a Helium deployment: a certificate
// authority and the node certificates it issues.
package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// Authority is a certificate authority issuing the node certificates of a Helium
// deployment. It is meant for tests and for development deployments; a production
// deployment is expected to bring its own PKI.
//
// A node certificate carries the node id as its dNSName SAN, which is how the helper
// authenticates its peers and how the peers authenticate the helper.
type Authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey

	// CertPEM is the PEM-encoded certificate of the authority, to be distributed to
	// all the nodes as their CACert.
	CertPEM []byte
}

// NewAuthority generates a new self-signed certificate authority valid for the given
// duration.
func NewAuthority(name string, validity time.Duration) (*Authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("could not generate the CA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name, Organization: []string{"Helium"}},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("could not create the CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("could not parse the CA certificate: %w", err)
	}

	return &Authority{cert: cert, key: key, CertPEM: pemEncode("CERTIFICATE", der)}, nil
}

// Issue issues a certificate for the node with the given id, usable both as a server
// certificate (the helper) and as a client certificate (a peer). The id is set as the
// certificate's dNSName SAN. It returns the PEM-encoded certificate and private key.
func (a *Authority) Issue(nodeID string, validity time.Duration) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("could not generate the key of node %s: %w", nodeID, err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: nodeID, Organization: []string{"Helium"}},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
		DNSNames:              []string{nodeID},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create the certificate of node %s: %w", nodeID, err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("could not marshal the key of node %s: %w", nodeID, err)
	}

	return pemEncode("CERTIFICATE", der), pemEncode("PRIVATE KEY", keyDER), nil
}

func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("could not generate a certificate serial number: %w", err)
	}
	return serial, nil
}

func pemEncode(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}
