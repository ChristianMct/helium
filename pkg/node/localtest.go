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
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/ldsec/helium/pkg/objectstore"
	"github.com/ldsec/helium/pkg/services/setup"
	cryptoUtil "github.com/ldsec/helium/pkg/utils/crypto"

	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/transport/centralized"
	"github.com/tuneinsight/lattigo/v4/bgv"
	"github.com/tuneinsight/lattigo/v4/drlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"golang.org/x/net/context"
	"google.golang.org/grpc/test/bufconn"
)

// LocalTestConfig is a configuration structure for LocalTest types. It is used to
// specify the number of full, light and helper nodes in the local test.
type LocalTestConfig struct {
	FullNodes     int // Number of full nodes in the session
	LightNodes    int // Number of light nodes in the session
	HelperNodes   int // number of helper nodes (full nodes that are not in the session key)
	ExternalNodes int
	Session       *pkg.SessionParameters
	//DoThresholdSetup bool
	InsecureChannels  bool // are we using (m)TLS to establish the channels between nodes?
	ObjectStoreConfig *objectstore.Config
	SimSetup          *setup.Description // if set, replace the pk backend for the compute service with a simulated setup backend
}

// LocalTest represent a local test setting with several nodes and a single
// session with group secret key.
type LocalTest struct {
	Nodes         []*Node
	FullNodes     []*Node
	LightNodes    []*Node
	HelperNodes   []*Node
	ExternalNodes []*Node
	Params        bgv.Parameters

	SkIdeal     *rlwe.SecretKey
	NodeConfigs []Config
	pkg.NodesList
	//compute.PublicKeyBackend
}

// NewLocalTest creates a new LocalTest from the configuration and returns it.
func NewLocalTest(config LocalTestConfig) (test *LocalTest) {
	test = new(LocalTest)
	//memPkBackend := &compute.MemoryKeyBackend{}
	//test.PublicKeyBackend = memPkBackend
	test.NodeConfigs, test.NodesList = genNodeConfigs(config)
	test.Nodes = make([]*Node, config.FullNodes+config.LightNodes+config.HelperNodes+config.ExternalNodes)
	for i, nc := range test.NodeConfigs {
		var err error
		test.Nodes[i], err = NewNode(nc, test.NodesList)
		if err != nil {
			panic(err)
		}
	}
	test.FullNodes = test.Nodes[:config.FullNodes]
	test.LightNodes = test.Nodes[config.FullNodes : config.FullNodes+config.LightNodes]
	test.HelperNodes = test.Nodes[config.FullNodes+config.LightNodes : config.FullNodes+config.LightNodes+config.HelperNodes]
	test.ExternalNodes = test.Nodes[config.FullNodes+config.LightNodes+config.HelperNodes:]

	// initialize the session-related fields if session parameters are given
	if config.Session != nil {
		var err error
		test.Params, err = bgv.NewParametersFromLiteral(config.Session.RLWEParams)
		if err != nil {
			panic(err)
		}

		sess := make([]*pkg.Session, len(test.SessionNodes()))
		test.SkIdeal = rlwe.NewSecretKey(test.Params)
		for i, n := range test.SessionNodes() {
			// computes the ideal secret-key for the test
			sess[i], _ = n.GetSessionFromID("test-session")
			sk, err := sess[i].GetSecretKey()
			if err != nil {
				panic(err)
			}
			test.Params.RingQP().AtLevel(test.SkIdeal.Value.Q.Level(), test.SkIdeal.Value.P.Level()).Add(sk.Value, test.SkIdeal.Value, test.SkIdeal.Value)
		}

		// initialise key generation
		// if config.SimSetup != nil {
		// 	kg := rlwe.NewKeyGenerator(test.Params)
		// 	sk := test.SkIdeal
		// 	if config.SimSetup.Cpk != nil {
		// 		cpk, err := kg.GenPublicKeyNew(sk)
		// 		if err != nil {
		// 			panic(err)
		// 		}
		// 		memPkBackend.PublicKey = cpk
		// 	}
		// 	for _, gkrec := range config.SimSetup.GaloisKeys {
		// 		gk, err := kg.GenGaloisKeyNew(gkrec.GaloisEl, sk)
		// 		if err != nil {
		// 			panic(err)
		// 		}
		// 		memPkBackend.GaloisKeys[gk.GaloisElement] = gk

		// 	}
		// 	if config.SimSetup.Rlk != nil {
		// 		rlk, err := kg.GenRelinearizationKeyNew(sk.CopyNew())
		// 		if err != nil {
		// 			panic(err)
		// 		}
		// 		memPkBackend.RelinearizationKey = rlk
		// 	}

		// 	for _, node := range test.Nodes {
		// 		node.GetComputeService().SetPublicKeyBackend(memPkBackend)
		// 	}
		// }

		// if config.Session.T != 0 && config.Session.T < len(test.SessionNodes()) && config.DoThresholdSetup {
		// 	shares := make(map[pkg.NodeID]map[pkg.NodeID]*drlwe.ShamirSecretShare, len(test.SessionNodes()))
		// 	thresholdizer := drlwe.NewThresholdizer(test.Params)
		// 	for i, ni := range test.SessionNodes() {
		// 		shares[ni.id] = make(map[pkg.NodeID]*drlwe.ShamirSecretShare, len(test.SessionNodes()))
		// 		sk, err := sess[i].GetSecretKey()
		// 		if err != nil {
		// 			panic(err)
		// 		}
		// 		shamirPoly, _ := thresholdizer.GenShamirPolynomial(config.Session.T, sk)
		// 		for _, nj := range test.SessionNodes() {
		// 			shares[ni.id][nj.id] = thresholdizer.AllocateThresholdSecretShare()
		// 			thresholdizer.GenShamirSecretShare(sess[i].SPKS[nj.ID()], shamirPoly, shares[ni.id][nj.id])
		// 		}
		// 	}
		// 	for i, ni := range test.SessionNodes() {
		// 		tsk := thresholdizer.AllocateThresholdSecretShare()
		// 		for _, nj := range test.SessionNodes() {
		// 			thresholdizer.AggregateShares(shares[nj.id][ni.id], tsk, tsk)
		// 		}
		// 		sess[i].SetTSK(tsk)
		// 	}
		// }
	}

	return test
}

// genNodeConfigs generates the necessary NodeConfig for each party specified in the LocalTestConfig.
func genNodeConfigs(config LocalTestConfig) ([]Config, pkg.NodesList) {

	ncs := make([]Config, 0, config.FullNodes+config.HelperNodes+config.LightNodes+config.ExternalNodes)
	nl := pkg.NodesList{}

	sessionNodesIds := make([]pkg.NodeID, 0, config.FullNodes+config.LightNodes)
	nodeShamirPks := make(map[pkg.NodeID]drlwe.ShamirPublicPoint)

	shamirPk := 1

	for i := 0; i < config.FullNodes; i++ {
		nodeID := pkg.NodeID("full-" + strconv.Itoa(i))
		nc := Config{
			ID:      nodeID,
			Address: pkg.NodeAddress("local"),
		}
		ncs = append(ncs, nc)
		nl = append(nl, struct {
			pkg.NodeID
			pkg.NodeAddress
			DelegateID pkg.NodeID
		}{nc.ID, nc.Address, ""})
		sessionNodesIds = append(sessionNodesIds, nc.ID)

		nodeShamirPks[nc.ID] = drlwe.ShamirPublicPoint(shamirPk)
		shamirPk++
	}

	for i := 0; i < config.LightNodes; i++ {
		nodeID := pkg.NodeID("light-" + strconv.Itoa(i))
		nc := Config{
			ID:       nodeID,
			HelperID: "helper-0",
		}
		ncs = append(ncs, nc)
		nl = append(nl, struct {
			pkg.NodeID
			pkg.NodeAddress
			DelegateID pkg.NodeID
		}{nc.ID, nc.Address, pkg.NodeID(fmt.Sprintf("helper-%d", i%config.HelperNodes))})
		sessionNodesIds = append(sessionNodesIds, nc.ID)

		nodeShamirPks[nc.ID] = drlwe.ShamirPublicPoint(shamirPk)
		shamirPk++
	}

	for i := 0; i < config.HelperNodes; i++ {
		nodeID := pkg.NodeID("helper-" + strconv.Itoa(i))
		nc := Config{
			ID:       nodeID,
			Address:  pkg.NodeAddress("local"),
			HelperID: "helper-0",
		}
		ncs = append(ncs, nc)
		nl = append(nl, struct {
			pkg.NodeID
			pkg.NodeAddress
			DelegateID pkg.NodeID
		}{nc.ID, nc.Address, ""})
	}

	for i := 0; i < config.ExternalNodes; i++ {
		nodeID := pkg.NodeID("external-" + strconv.Itoa(i))
		nc := Config{
			ID: nodeID,
		}
		ncs = append(ncs, nc)
		nl = append(nl, struct {
			pkg.NodeID
			pkg.NodeAddress
			DelegateID pkg.NodeID
		}{nc.ID, nc.Address, pkg.NodeID(fmt.Sprintf("helper-%d", i%config.HelperNodes))})
	}

	tlsConfigs, err := createTLSConfigs(config, nl)
	if err != nil {
		log.Println(err)
		panic("failed to generate tls configs - got err")
	}
	for i := range ncs {
		ncs[i].TLSConfig = tlsConfigs[ncs[i].ID]
	}

	// sets session-specific variables with test values
	if config.Session != nil {
		config.Session.ID = "test-session" // forces the session id
		config.Session.Nodes = sessionNodesIds
		config.Session.PublicSeed = []byte{'l', 'a', 't', 't', 'i', 'g', '0'}

		for i := range ncs {
			ncs[i].SessionParameters = []pkg.SessionParameters{*config.Session}
			ncs[i].SessionParameters[0].ShamirPks = nodeShamirPks // forces the Shamir pts
		}
	}

	objstoreconf := objectstore.Config{
		BackendName: "mem",
	}
	if config.ObjectStoreConfig != nil {
		objstoreconf = *config.ObjectStoreConfig
	}
	for i := range ncs {
		ncs[i].ObjectStoreConfig = objstoreconf
	}

	return ncs, nl
}

type nodeCrypto struct {
	pubkey crypto.PublicKey
	skey   crypto.PrivateKey
	cert   x509.Certificate
}

func createTLSConfigs(testConfig LocalTestConfig, nodeList pkg.NodesList) (map[pkg.NodeID]centralized.TLSConfig, error) {

	tlsConfigs := make(map[pkg.NodeID]centralized.TLSConfig, len(nodeList))

	if testConfig.InsecureChannels {
		for _, n := range nodeList {
			tlsConfigs[n.NodeID] = centralized.TLSConfig{InsecureChannels: true}
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

	peerCrypto := make(map[pkg.NodeID]nodeCrypto, len(nodeList))
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
		peerPKs := make(map[pkg.NodeID]string, len(nodeList)-1) // fully connected nodes
		peerCerts := make(map[pkg.NodeID]string, len(nodeList)-1)

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

		tlsConfigs[nodeID] = centralized.TLSConfig{
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

const buffConBufferSize = 65 * 1024 * 1024

// Start creates some in-memory connections between the nodes and returns
// when all nodes are connected.
func (lc LocalTest) Start() {
	lis := bufconn.Listen(buffConBufferSize)

	go lc.HelperNodes[0].srv.Server.Serve(lis)

	var wg sync.WaitGroup
	for _, node := range lc.SessionNodes() {
		node := node
		wg.Add(1)
		go func() {
			err := node.cli.ConnectWithDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() })
			if err != nil {
				log.Printf("node %s failed to connect: %v", node.ID(), err)
				return
			}
			wg.Done()
		}()
	}
	wg.Wait()
}

// SessionNodes returns the set of nodes in the local test that are part of the
// session.
func (lc LocalTest) SessionNodes() []*Node {
	return lc.Nodes[:len(lc.FullNodes)+len(lc.LightNodes)]
}

func (lc LocalTest) SessionNodesIds() []pkg.NodeID {
	sessionNodes := lc.SessionNodes()
	ids := make([]pkg.NodeID, len(sessionNodes))
	for i, node := range sessionNodes {
		ids[i] = node.id
	}
	return ids
}

// NodeIds returns the node ideas of all nodes in the local test.
func (lc LocalTest) NodeIds() []pkg.NodeID {
	ids := make([]pkg.NodeID, len(lc.Nodes))
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
