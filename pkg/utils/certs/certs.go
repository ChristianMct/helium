// package crypto provides utility functions for managing certificates.
package certs

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // sha1 is needed here
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

// A few of the possible PEM headers.
// Based on https://github.com/openssl/openssl/blob/master/include/openssl/pem.h

const PemStringX509Old = "X509 CERTIFICATE"
const PemStringX509 = "CERTIFICATE"
const PemStringX509Req = "CERTIFICATE REQUEST"
const PemStringX509Crl = "X509 CRL"
const PemStringEvpPkey = "ANY PRIVATE KEY"
const PemStringPublic = "PUBLIC KEY"
const PemStringRsa = "RSA PRIVATE KEY"
const PemStringRsaPublic = "RSA PUBLIC KEY"
const PemStringPkcs7 = "PKCS7"
const PemStringPkcs8 = "ENCRYPTED PRIVATE KEY"
const PemStringPkcs8inf = "PRIVATE KEY"
const PemStringDhparams = "DH PARAMETERS"
const PemStringSslSession = "SSL SESSION PARAMETERS"
const PemStringDsaparams = "DSA PARAMETERS"
const PemStringEcdsaPublic = "ECDSA PUBLIC KEY"
const PemStringEcparameters = "EC PARAMETERS"
const PemStringEcprivatekey = "EC PRIVATE KEY"
const PemStringParameters = "PARAMETERS"

// PEMEncode encodes bu as a PEM blob given the block type.
func PEMEncode(bu []byte, blockType string) (*bytes.Buffer, error) {
	switch blockType {
	case PemStringX509, PemStringX509Old, PemStringPublic, PemStringPkcs8inf, PemStringEvpPkey, PemStringX509Req:
	default:
		return nil, fmt.Errorf("unknown type: %s", blockType)
	}
	pemBuf := new(bytes.Buffer)

	err := pem.Encode(pemBuf, &pem.Block{
		Type:  blockType,
		Bytes: bu,
	})

	if err != nil {
		return nil, fmt.Errorf("pem encode failed: %w", err)
	}
	return pemBuf, nil
}

func _asnSeqEncode(targets []string) []byte {
	var elems []byte
	byteLen := 0
	for _, t := range targets {
		e := []byte{0x82, uint8(len(t))}
		e = append(e, []byte(t)...)
		byteLen += len(e)
		elems = append(elems, e...)
	}
	seq := []byte{0x30, uint8(byteLen)}
	seq = append(seq, elems...)
	return seq
}

func _asnSKIDEncode(pk ed25519.PublicKey) []byte {
	asn := make([]byte, 22)
	asn[0] = 0x04
	asn[1] = 0x14
	pkHash := sha1.Sum(pk) //nolint:gosec // sha1 is what the cert expects currently
	for i, b := range pkHash {
		asn[i+2] = b
	}
	return asn
}

// GenCSR generates a test certificate signing request.
func GenCSR(commonName string, pk ed25519.PublicKey, sk ed25519.PrivateKey) ([]byte, error) {
	// create a signing request for the CA
	subject := pkix.Name{
		Organization:  []string{"Helium Node"},
		Country:       []string{"CH"},
		Locality:      []string{"Lausanne"},
		StreetAddress: []string{"Bâtiment C"},
		PostalCode:    []string{"1015"},
		CommonName:    commonName,
	}

	keyUsage, _ := hex.DecodeString("030204F0")
	extKeyUsage, _ := hex.DecodeString("301406082B0601050507030106082B06010505070302")
	basicConstraints, _ := hex.DecodeString("3000")
	dnsNames := []string{commonName, "www." + commonName}

	csrTmp := x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: x509.PureEd25519, // todo: should this be prehashed?
		DNSNames:           dnsNames,
		ExtraExtensions: []pkix.Extension{
			// key usage
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 15},
				Critical: true,
				Value:    keyUsage,
			},
			// extKeyUsage
			{
				Id:    asn1.ObjectIdentifier{2, 5, 29, 37},
				Value: extKeyUsage,
			},
			// basic constraints
			{
				Id:    asn1.ObjectIdentifier{2, 5, 29, 19},
				Value: basicConstraints,
			},
			// subjectAltName
			{
				Id:    asn1.ObjectIdentifier{2, 5, 29, 17},
				Value: _asnSeqEncode(dnsNames),
			},
			// subjKeyIden
			{
				Id:    asn1.ObjectIdentifier{2, 5, 29, 14},
				Value: _asnSKIDEncode(pk),
			},
		},
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &csrTmp, sk)
	if err != nil {
		return nil, fmt.Errorf("could not create cert: %w", err)
	}

	pemCSR, err := PEMEncode(csr, PemStringX509Req)
	if err != nil {
		return nil, fmt.Errorf("could not encode cert: %w", err)
	}
	return pemCSR.Bytes(), nil
}

// ToPEM returns as a PEM-encoded []byte representation
func ToPEM(obj any) ([]byte, error) {
	var objBytes []byte
	var blockType string
	var err error
	switch obj := obj.(type) {
	case x509.Certificate:
		objBytes = obj.Raw
		blockType = PemStringX509
	case ed25519.PrivateKey:
		objBytes, err = x509.MarshalPKCS8PrivateKey(obj)
		blockType = PemStringPkcs8inf
	case ed25519.PublicKey:
		objBytes, err = x509.MarshalPKIXPublicKey(obj)
		blockType = PemStringPublic
	default:
		err = fmt.Errorf("unsupported object type: %T", obj)
	}
	if err != nil {
		return nil, err
	}
	buf, err := PEMEncode(objBytes, blockType)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ReadPEM decodes data as a PEM object and returns it.
func ReadPEM(data []byte) (any, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM: expecting single-block input data")
	}
	switch block.Type {
	case "CERTIFICATE":
		crt, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse cert: %w", err)
		}
		return crt, nil
	case "PRIVATE KEY":
		sk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse private key: %w", err)
		}
		return sk, nil
	case "PUBLIC KEY":
		pk, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse public key: %w", err)
		}
		return pk, nil
	default:
		return nil, fmt.Errorf("unhandled PEM block type: %s", block.Type)
	}
}

func ParsePk(pkBytes []byte) (crypto.PublicKey, error) {
	obj, err := ReadPEM(pkBytes)
	if err != nil {
		return nil, err
	}
	pk, ok := obj.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("wrong public key type, expecting %T but got %T", pk, obj)
	}
	return pk, nil
}

func ParseCert(certBytes []byte) (*x509.Certificate, error) {
	obj, err := ReadPEM(certBytes)
	if err != nil {
		return nil, err
	}
	asX509, ok := obj.(*x509.Certificate)
	if !ok {
		return nil, fmt.Errorf("wrong certificate type, expecting %T but got %T", asX509, obj)
	}
	return asX509, nil
}

func ParseSk(skBytes []byte) (crypto.PrivateKey, error) {
	obj, err := ReadPEM(skBytes)
	if err != nil {
		return nil, err
	}
	sk, ok := obj.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("wrong private key type, expecting %T but got %T", sk, obj)
	}
	return sk, nil
}

func X509ToTLS(cert *x509.Certificate, sk ed25519.PrivateKey) tls.Certificate {
	// Todo: i'd like sk to be just crypto.PrivateKey but type coercion doesn't seem to work properly

	return tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  sk, Leaf: cert,
	}
}
