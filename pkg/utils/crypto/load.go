package crypto

import (
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

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

func ReadPEM(data []byte) (any, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM: expecting single-block input data")
	}
	switch block.Type {
	case "CERTIFICATE":
		crt, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse cert: %s", err)
		}
		return crt, nil
	case "PRIVATE KEY":
		sk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse private key: %s", err)
		}
		return sk, nil
	case "PUBLIC KEY":
		pk, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse public key: %s", err)
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
