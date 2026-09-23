package helper

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/api/pb"
	"github.com/ChristianMct/helium/heliumtest"
	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/utils"
	"github.com/ChristianMct/helium/utils/certs"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const testCertValidity = time.Hour

// testCA is a certificate authority issuing the node certificates of a test.
type testCA struct {
	*certs.Authority
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	ca, err := certs.NewAuthority("helium-test-ca", testCertValidity)
	require.NoError(t, err)
	return &testCA{Authority: ca}
}

// configFor returns the TLS config of a node whose certificate is issued by the CA
// for certID. certID is the identity the certificate attests to, which is the node's
// own id except in the impersonation tests.
func (ca *testCA) configFor(t *testing.T, certID helium.NodeID) TLSConfig {
	t.Helper()
	certPEM, keyPEM, err := ca.Issue(string(certID), testCertValidity)
	require.NoError(t, err)
	return TLSConfig{
		CACert:  string(ca.CertPEM),
		OwnCert: string(certPEM),
		OwnKey:  string(keyPEM),
	}
}

// withTLS provisions the helper and every peer of the local test with a certificate
// from ca, so that the existing newServer/newClient helpers run over mutual TLS.
func (lt *localTest) withTLS(t *testing.T, ca *testCA) *localTest {
	t.Helper()
	for nid, config := range lt.configs {
		config.TLS = ca.configFor(t, nid)
		lt.configs[nid] = config
	}
	return lt
}

// TestTLSSetup runs the full setup phase over mutual TLS, checking that the whole
// stack (event stream, share submission, aggregation) works under authenticated
// channels.
func TestTLSSetup(t *testing.T) {
	const N, T = 3, 2
	lt := newLocalTest(t, N, T).withTLS(t, newTestCA(t))
	ctx := testContext(t)

	app := helium.App{Setup: &testSetupDescription}

	hsv, lis := lt.newServer(t)
	clients := lt.newConnectedClients(t, lis, lt.peerIDs...)
	require.NoError(t, runAll(ctx, app, hsv, clients))

	heliumtest.CheckSetup(ctx, t, *app.Setup, hsv, lt.RlweParams, lt.SkIdeal, N)
}

// TestTLSConfigValidation checks that a misprovisioned node fails to start, rather
// than failing on its first handshake.
func TestTLSConfigValidation(t *testing.T) {
	ca := newTestCA(t)

	t.Run("CertForAnotherNode", func(t *testing.T) {
		lt := newLocalTest(t, 2, 2)
		config := lt.configs["peer-0"]
		config.TLS = ca.configFor(t, "peer-1") // wrong identity
		_, err := NewClient(config, lt.secretProvider)
		require.ErrorContains(t, err, "does not carry peer-0 as a dNSName SAN")
	})

	t.Run("NoMaterial", func(t *testing.T) {
		lt := newLocalTest(t, 2, 2)
		config := lt.configs["peer-0"]
		config.TLS = TLSConfig{} // neither insecure nor provisioned
		_, err := NewClient(config, lt.secretProvider)
		require.ErrorContains(t, err, "no CA certificate")
	})

	t.Run("NonDNSNodeID", func(t *testing.T) {
		lt := newLocalTest(t, 2, 2)
		config := lt.configs["peer-0"]
		config.ID = "Peer_0"
		_, err := NewClient(config, lt.secretProvider)
		require.ErrorContains(t, err, "lowercase DNS names")
	})
}

// TestTLSOriginChecks checks that the helper rejects objects whose declared origin
// does not match the identity certified by the caller's certificate.
func TestTLSOriginChecks(t *testing.T) {
	ca := newTestCA(t)
	lt := newLocalTest(t, 2, 2).withTLS(t, ca)
	_, lis := lt.newServer(t)
	ctx := testContext(t)

	// an authentic peer-0: correctly certified, in the node list.
	cli := newRawClient(t, "peer-0", lt.configs["peer-0"].TLS, lis)

	t.Run("ShareFromAnotherNode", func(t *testing.T) {
		share := testShare(t, "peer-1")
		_, err := cli.PutShare(ctx, share)
		require.Equal(t, codes.PermissionDenied, status.Code(err))
		require.ErrorContains(t, err, "does not match the authenticated node peer-0")
	})

	t.Run("PreAggregatedShare", func(t *testing.T) {
		share := testShare(t, "peer-0", "peer-1")
		_, err := cli.PutShare(ctx, share)
		require.Equal(t, codes.PermissionDenied, status.Code(err))
	})

	t.Run("ShareWithNoOrigin", func(t *testing.T) {
		share := testShare(t)
		_, err := cli.PutShare(ctx, share)
		require.Equal(t, codes.PermissionDenied, status.Code(err))
	})

	t.Run("OwnShareReachesTheRunner", func(t *testing.T) {
		// the origin check passes, so the share is handed to the protocol runner,
		// which rejects it because no such protocol is running. Anything other than
		// FailedPrecondition would mean the share was stopped by the origin check.
		share := testShare(t, "peer-0")
		_, err := cli.PutShare(ctx, share)
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
	})

	t.Run("OperandOwnedByAnotherNode", func(t *testing.T) {
		_, err := cli.PutCiphertext(ctx, lt.testOperand(t, "//peer-1/test-circuit-0/in"))
		require.Equal(t, codes.PermissionDenied, status.Code(err))
		require.ErrorContains(t, err, "is not owned by the authenticated node peer-0")
	})

	t.Run("OwnOperandReachesTheRunner", func(t *testing.T) {
		// as above: past the origin check, the circuit runner rejects it because no
		// such circuit is running.
		_, err := cli.PutCiphertext(ctx, lt.testOperand(t, "//peer-0/test-circuit-0/in"))
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
	})
}

// newRawClient returns a gRPC client stub presenting the given TLS material,
// connected to lis. Unlike Client, it bypasses the session machinery and sends
// whatever it is given: it is how the tests submit the impersonating messages that
// an honest Client never would.
func newRawClient(t *testing.T, self helium.NodeID, tlsConfig TLSConfig, lis *bufconn.Listener) pb.HeliumClient {
	t.Helper()
	creds, err := tlsConfig.clientCredentials(self, "helper")
	require.NoError(t, err)

	conn, err := grpc.NewClient("passthrough:///helper",
		grpc.WithTransportCredentials(creds),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }))
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	return pb.NewHeliumClient(conn)
}

// testShare returns a syntactically valid share declaring the given origins.
func testShare(t *testing.T, from ...helium.NodeID) *pb.Share {
	t.Helper()
	share := protocols.Share{
		ShareMetadata: protocols.ShareMetadata{
			ProtocolID:   "test-protocol",
			ProtocolType: protocols.CKG,
			From:         utils.NewSet(from),
		},
		MHEShare: protocols.CKG.Share(),
	}
	apiShare, err := GetShare(&share)
	require.NoError(t, err)
	return apiShare
}

// testOperand returns a syntactically valid operand with the given id.
func (lt *localTest) testOperand(t *testing.T, id helium.OperandID) *pb.Ciphertext {
	t.Helper()
	op := &helium.Operand{ID: id, Ciphertext: rlwe.NewCiphertext(lt.RlweParams, 1, lt.RlweParams.MaxLevel())}
	apiCt, err := GetOperand(op)
	require.NoError(t, err)
	return apiCt
}
