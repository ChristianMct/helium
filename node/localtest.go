package node

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"strconv"
	"time"

	"github.com/ChristianMct/helium/coordinator"
	"github.com/ChristianMct/helium/objectstore"
	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/services/compute"
	"github.com/ChristianMct/helium/services/setup"
	cryptoUtil "github.com/ChristianMct/helium/utils/certs"

	"github.com/ChristianMct/helium/sessions"
	drlwe "github.com/tuneinsight/lattigo/v5/mhe"
	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
)

// LocalTestConfig is a configuration structure for LocalTest types.
type LocalTestConfig struct {
	PeerNodes         int // Number of peer nodes in the session
	SessionParams     *sessions.Parameters
	InsecureChannels  bool                // use TLS for this test. TODO: fix TLS
	ObjectStoreConfig *objectstore.Config // nodes's object store configuration for this test
}

// LocalTest represent a local test setting with several nodes and a single
// session with group secret key.
type LocalTest struct {
	Nodes      []*Node
	PeerNodes  []*Node
	HelperNode *Node
	Params     bgv.Parameters

	*sessions.TestSession
	HelperConfig    Config
	SessNodeConfigs []Config
	List

	transport   testTransport
	coordinator Coordinator
}

// NewLocalTest creates a new LocalTest from the configuration and returns it.
func NewLocalTest(config LocalTestConfig) (test *LocalTest, err error) {
	test = new(LocalTest)

	helperID := sessions.NodeID("helper")
	sessNodesID := make([]sessions.NodeID, config.PeerNodes)
	shamirPks := make(map[sessions.NodeID]drlwe.ShamirPublicPoint, config.PeerNodes)
	test.List = make(List, 1+config.PeerNodes)
	for i := range sessNodesID {
		nid := sessions.NodeID("peer-" + strconv.Itoa(i))
		sessNodesID[i] = nid
		shamirPks[nid] = drlwe.ShamirPublicPoint(i + 1)
		test.List[i] = Info{NodeID: nid}
	}
	test.List[len(sessNodesID)] = Info{NodeID: helperID, Address: "local"}

	config.SessionParams.Nodes = sessNodesID
	config.SessionParams.ShamirPks = shamirPks
	config.SessionParams.ID = "test-session"
	config.SessionParams.PublicSeed = []byte{'l', 'a', 't', 't', 'i', 'g', '0'}

	test.SessNodeConfigs, test.HelperConfig = genNodeConfigs(config, test.List)

	if config.SessionParams != nil {
		test.TestSession, err = sessions.NewTestSessionFromParams(*config.SessionParams, test.HelperConfig.ID)
		if err != nil {
			return nil, err
		}
	}

	secrets, err := sessions.GenTestSecretKeys(test.TestSession.SessParams)
	if err != nil {
		return nil, err
	}

	test.Nodes = make([]*Node, 1+config.PeerNodes)
	test.HelperNode, err = New(test.HelperConfig, test.List, nil)
	if err != nil {
		return nil, err
	}
	test.Nodes[0] = test.HelperNode
	for i, nc := range test.SessNodeConfigs {
		var err error
		test.Nodes[i+1], err = New(nc, test.List, func(_ sessions.ID, _ sessions.NodeID) (*sessions.Secrets, error) {
			return secrets[nc.ID], nil
		})
		if err != nil {
			return nil, err
		}
	}

	test.PeerNodes = test.Nodes[1:]

	test.coordinator = coordinator.NewTestCoordinator[Event](helperID)
	test.transport = *NewTestTransport(test.HelperNode.id, test.HelperNode.setup, test.HelperNode.compute)

	var ok bool
	test.Params, ok = test.HelperSession.Params.(bgv.Parameters)
	if !ok {
		return nil, fmt.Errorf("local tests are currently supported for BGV parameters only, got %T", test.HelperSession.Params)
	}

	return test, nil
}

// genNodeConfigs generates the necessary NodeConfig for each party specified in the LocalTestConfig.
func genNodeConfigs(config LocalTestConfig, nl List) (sessNodesConfig []Config, helperNodeConfig Config) {

	tlsConfigs, err := createTLSConfigs(config, nl)
	if err != nil {
		log.Println(err)
		panic("failed to generate tls configs - got err")
	}

	objstoreconf := objectstore.Config{
		BackendName: "mem",
	}
	if config.ObjectStoreConfig != nil {
		objstoreconf = *config.ObjectStoreConfig
	}

	sp := config.SessionParams
	hid := nl[len(nl)-1].NodeID
	sessNodesConfig = make([]Config, config.PeerNodes)
	nodeExecConfig := protocols.ExecutorConfig{
		MaxParticipation: 1,
		MaxAggregation:   -1,
	}
	for i := range sessNodesConfig {
		nid := nl[i].NodeID
		sessNodesConfig[i] = Config{
			ID:                nid,
			HelperID:          hid,
			SessionParameters: []sessions.Parameters{*sp},
			TLSConfig:         tlsConfigs[nid],
			ObjectStoreConfig: objstoreconf,
			SetupConfig: setup.ServiceConfig{
				Protocols: nodeExecConfig,
			},
			ComputeConfig: compute.ServiceConfig{
				Protocols:            nodeExecConfig,
				MaxCircuitEvaluation: 1,
			},
		}
	}

	helperExecConfig := protocols.ExecutorConfig{
		MaxProtoPerNode:  1,
		MaxAggregation:   1,
		MaxParticipation: -1,
	}
	helperNodeConfig = Config{
		ID:                hid,
		HelperID:          hid,
		SessionParameters: []sessions.Parameters{*sp},
		TLSConfig:         tlsConfigs[hid],
		ObjectStoreConfig: objstoreconf,
		SetupConfig: setup.ServiceConfig{
			Protocols: helperExecConfig,
		},
		ComputeConfig: compute.ServiceConfig{
			Protocols:            helperExecConfig,
			MaxCircuitEvaluation: 1,
		},
	}

	return sessNodesConfig, helperNodeConfig
}

type nodeCrypto struct {
	pubkey crypto.PublicKey
	skey   crypto.PrivateKey
	cert   x509.Certificate
}

func createTLSConfigs(testConfig LocalTestConfig, nodeList List) (map[sessions.NodeID]TLSConfig, error) {

	tlsConfigs := make(map[sessions.NodeID]TLSConfig, len(nodeList))

	if testConfig.InsecureChannels {
		for _, n := range nodeList {
			tlsConfigs[n.NodeID] = TLSConfig{InsecureChannels: true}
		}
		return tlsConfigs, nil
	}

	caPubKey, caPrivKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}

	caCertTemp := &x509.Certificate{
		SerialNumber: big.NewInt(1337),
		Subject: pkix.Name{
			Organization: []string{"Helium Cert, SA"},
			Country:      []string{"CH"},
			Locality:     []string{"Lausanne"},
			CommonName:   "Helium Cert",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, caCertTemp, caCertTemp, caPubKey, caPrivKey)
	if err != nil {
		return nil, err
	}
	dummy, _ := x509.ParseCertificate(caBytes)
	caCert := *dummy

	caCertPem, err := cryptoUtil.ToPEM(caCert)
	if err != nil {
		return nil, err
	}

	peerCrypto := make(map[sessions.NodeID]nodeCrypto, len(nodeList))
	// sign certs for everyone
	for _, peer := range nodeList {
		pubkey, skey, errGenKey := ed25519.GenerateKey(nil)
		if errGenKey != nil {
			return nil, errGenKey
		}
		csrbytes, errGenCSR := cryptoUtil.GenCSR(string(peer.NodeID), pubkey, skey)
		if errGenCSR != nil {
			return nil, errGenCSR
		}
		csrPEM, _ := pem.Decode(csrbytes)
		csr, errParseCertReq := x509.ParseCertificateRequest(csrPEM.Bytes)
		if errParseCertReq != nil {
			return nil, errParseCertReq
		}
		certTemp := x509.Certificate{
			SerialNumber:       big.NewInt(1337),
			Subject:            csr.Subject,
			NotBefore:          time.Now(),
			NotAfter:           time.Now().AddDate(10, 0, 0),
			ExtraExtensions:    csr.Extensions,
			DNSNames:           csr.DNSNames,
			EmailAddresses:     csr.EmailAddresses,
			IPAddresses:        csr.IPAddresses,
			URIs:               csr.URIs,
			Signature:          csr.Signature,
			SignatureAlgorithm: csr.SignatureAlgorithm,

			PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
			PublicKey:          csr.PublicKey,
		}
		cert, errCreateCert := x509.CreateCertificate(rand.Reader, &certTemp, &caCert, pubkey, caPrivKey)
		if errCreateCert != nil {
			return nil, errCreateCert
		}
		certObj, errParseCert := x509.ParseCertificate(cert)
		if errParseCert != nil {
			return nil, errParseCert
		}
		peerCrypto[peer.NodeID] = nodeCrypto{
			pubkey: pubkey,
			skey:   skey,
			cert:   *certObj,
		}
	}

	// create the tls configs
	for nodeID, nodeCrypo := range peerCrypto {
		peerPKs := make(map[sessions.NodeID]string, len(nodeList)-1) // fully connected nodes
		peerCerts := make(map[sessions.NodeID]string, len(nodeList)-1)

		var skPem, pkPem, certPem []byte
		skPem, err = cryptoUtil.ToPEM(nodeCrypo.skey)
		if err != nil {
			return nil, err
		}
		pkPem, err = cryptoUtil.ToPEM(nodeCrypo.pubkey)
		if err != nil {
			return nil, err
		}
		certPem, err = cryptoUtil.ToPEM(nodeCrypo.cert)
		if err != nil {
			return nil, err
		}

		for otherNodeID, otherNodeCrypto := range peerCrypto {
			if nodeID == otherNodeID {
				continue
			}
			peerPkPem, errPk := cryptoUtil.ToPEM(otherNodeCrypto.pubkey)
			if errPk != nil {
				return nil, errPk
			}
			peerCertPem, errCrt := cryptoUtil.ToPEM(otherNodeCrypto.cert)
			if errCrt != nil {
				return nil, errCrt
			}
			peerPKs[otherNodeID] = string(peerPkPem)
			peerCerts[otherNodeID] = string(peerCertPem)
		}

		tlsConfigs[nodeID] = TLSConfig{
			OwnSk:     string(skPem),
			OwnPk:     string(pkPem),
			OwnCert:   string(certPem),
			PeerPKs:   peerPKs,
			PeerCerts: peerCerts,
			CACert:    string(caCertPem),
		}
	}
	return tlsConfigs, nil
}

// SessionNodes returns the set of nodes in the local test that are part of the
// session.
func (lc LocalTest) SessionNodes() []*Node {
	return lc.Nodes[1:]
}

func (lc LocalTest) SessionNodesIds() []sessions.NodeID {
	sessionNodes := lc.SessionNodes()
	ids := make([]sessions.NodeID, len(sessionNodes))
	for i, node := range sessionNodes {
		ids[i] = node.id
	}
	return ids
}

// NodeIds returns the node ideas of all nodes in the local test.
func (lc LocalTest) NodeIds() []sessions.NodeID {
	ids := make([]sessions.NodeID, len(lc.Nodes))
	for i, node := range lc.Nodes {
		ids[i] = node.id
	}
	return ids
}

// Close releases all the resources allocated by a localtest.
func (lc LocalTest) Close() error {
	for _, node := range lc.Nodes {
		err := node.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
