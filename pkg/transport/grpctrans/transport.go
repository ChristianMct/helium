package grpctrans

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/circuits"
	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/protocols"
	"github.com/ldsec/helium/pkg/transport"
	"github.com/ldsec/helium/pkg/utils/crypto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

const MaxMsgSize = 1024 * 1024 * 32

// Transport is a type implementing the transport.Transport interface
// with gRPC services.
type Transport struct {
	id       pkg.NodeID
	nodeList pkg.NodesList

	address pkg.NodeAddress
	conns   map[pkg.NodeID]*grpc.ClientConn

	grpcServer   *grpc.Server
	statsHandler statsHandler

	setup   *setupTransport
	compute *computeTransport

	sigs     SignatureScheme
	tlsSetup *tlsSetup
}

// NewTransport creates a new Transport instance for the provided configuration.
func NewTransport(id pkg.NodeID, na pkg.NodeAddress, nl pkg.NodesList, tlsConf TLSConfig) (*Transport, error) {
	t := new(Transport)
	var err error
	t.id = id
	t.nodeList = nl
	t.conns = make(map[pkg.NodeID]*grpc.ClientConn)

	t.tlsSetup, err = t.getTLSSetup(tlsConf)
	if err != nil {
		return nil, fmt.Errorf("failed to load crypto material: %w", err)
	}

	if t.tlsSetup.withInsecureChannels {
		t.sigs = SignatureScheme{
			Type: api.SignatureType_NONE,
		}
	} else {
		t.sigs = SignatureScheme{
			Type: api.SignatureType_ED25519,
			sk:   t.tlsSetup.ownSk.(ed25519.PrivateKey),
		}
	}

	t.setup = t.newSetupTransport()
	t.compute = t.newComputeTransport()

	t.address = na
	return t, nil
}

func (t *Transport) RegisterSetupService(srv transport.SetupServiceHandler) {
	t.setup.registerService(srv)
}

func (t *Transport) RegisterComputeService(srv transport.ComputeServiceHandler) {
	t.compute.registerService(srv)
}

// Connect starts the transport. After calling Connect, the transport
// is running and delivering incoming/outgoing messages. It starts
// the server and client-ends of the gRPC service.
func (t *Transport) Connect() (err error) {

	var lis net.Listener
	if t.address != "" {
		lis, err = net.Listen("tcp", string(t.address))
		if err != nil {
			return fmt.Errorf("failed to listen: %w", err)
		}
	}

	return t.ConnectWithDialers(lis, t.dialers())
}

// ConnectWithDialers starts the transport with the provided listener and dialers. After calling Connect, the
// transport is running and delivering incoming/outgoing messages. It starts the server and client-ends of the gRPC service.
func (t *Transport) ConnectWithDialers(lis net.Listener, dialers map[pkg.NodeID]transport.Dialer) (err error) {

	if lis != nil {

		interceptors := []grpc.UnaryServerInterceptor{
			// t.serverSigChecker,
		}

		serverOpts := []grpc.ServerOption{
			grpc.MaxRecvMsgSize(MaxMsgSize),
			grpc.MaxSendMsgSize(MaxMsgSize),
			grpc.StatsHandler(&t.statsHandler),
			grpc.ChainUnaryInterceptor(interceptors...),
			grpc.KeepaliveParams(keepalive.ServerParameters{
				Time:    time.Second,
				Timeout: time.Second,
			}),
		}

		if !t.tlsSetup.withInsecureChannels {
			cert := crypto.X509ToTLS(t.tlsSetup.ownCert, t.tlsSetup.ownSk.(ed25519.PrivateKey))
			ca := x509.NewCertPool()
			ca.AddCert(t.tlsSetup.caCert)
			tlsConfig := &tls.Config{
				ClientAuth:   tls.RequireAndVerifyClientCert,
				Certificates: []tls.Certificate{cert},
				ClientCAs:    ca,
				// VerifyPeerCertificate: // TODO: can a server authenticate a client connection ?
				// VerifyConnection:
				MinVersion: tls.VersionTLS13,
			}
			serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))
		}

		t.grpcServer = grpc.NewServer(serverOpts...)

		t.grpcServer.RegisterService(&api.SetupService_ServiceDesc, t.setup)
		t.grpcServer.RegisterService(&api.ComputeService_ServiceDesc, &ComputeTransportHandler{t.compute})

		go func() {
			lis := lis
			if errSrv := t.grpcServer.Serve(lis); errSrv != nil {
				log.Panicf("%s | error while serving: %v\n", t.id, errSrv)
			}
		}()
	}

	var conns int
	for peerID, dialer := range dialers {

		if peerID == t.id {
			continue
		}

		interceptors := []grpc.UnaryClientInterceptor{
			// t.clientSigner,
		}

		opts := []grpc.DialOption{
			grpc.WithContextDialer(dialer),
			grpc.WithBlock(), // TODO: this prevents clients from sending errors on connection refused. Should check if there is a retry policy at client level
			grpc.WithConnectParams(grpc.ConnectParams{Backoff: backoff.DefaultConfig, MinConnectTimeout: 1 * time.Second}),
			grpc.WithDefaultCallOptions(
				grpc.MaxCallRecvMsgSize(MaxMsgSize),
				grpc.MaxCallSendMsgSize(MaxMsgSize)),
			grpc.WithStatsHandler(&t.statsHandler),
			grpc.WithChainUnaryInterceptor(interceptors...),
			grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: time.Second, Timeout: time.Minute}),
		}

		if !t.tlsSetup.withInsecureChannels {
			ownCert := crypto.X509ToTLS(t.tlsSetup.ownCert, t.tlsSetup.ownSk.(ed25519.PrivateKey))

			ca := x509.NewCertPool()
			ca.AddCert(t.tlsSetup.caCert)
			tlsConfig := &tls.Config{
				ServerName:   string(peerID),
				Certificates: []tls.Certificate{ownCert},
				RootCAs:      ca,
				// VerifyPeerCertificate:  //TODO: verify server has has cert for node ID
				// VerifyConnection:
				MinVersion: tls.VersionTLS13,
			}

			opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
		} else {
			opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		}

		t.conns[peerID], err = grpc.Dial(string(peerID), opts...)
		if err != nil {
			return fmt.Errorf("fail to dial: %w", err)
		}
		conns++
	}

	log.Printf("%s | is connected to %d peers\n", t.id, conns)

	t.setup.connect()
	t.compute.connect()

	return nil
}

func (t *Transport) GetSetupTransport() transport.SetupServiceTransport {
	return t.setup
}

func (t *Transport) GetComputeTransport() transport.ComputeServiceTransport {
	return t.compute
}

func (t *Transport) ResetNetworkStats() {
	t.statsHandler.mu.Lock()
	defer t.statsHandler.mu.Unlock()
	t.statsHandler.stats = transport.NetStats{}
}

func (t *Transport) GetNetworkStats() transport.NetStats {
	t.statsHandler.mu.Lock()
	defer t.statsHandler.mu.Unlock()
	return t.statsHandler.stats
}

func (t *Transport) PrintNetworkStats() {
	t.statsHandler.mu.Lock()
	defer t.statsHandler.mu.Unlock()
	log.Println(t.statsHandler.stats)
}

func (t *Transport) dialers() map[pkg.NodeID]transport.Dialer {
	dialers := make(map[pkg.NodeID]transport.Dialer)
	for _, peer := range t.nodeList {
		if peer.NodeAddress != "" {
			addr := peer.NodeAddress
			dialers[peer.NodeID] = func(_ context.Context, _ string) (net.Conn, error) {
				return net.Dial("tcp", addr.String())
			}
		}
	}
	return dialers
}

type SetupPeer struct {
	id                  pkg.NodeID
	protocolUpdateQueue chan protocols.StatusUpdate
	//peerReconnect       chan struct{}
	//protoUpdateStream   api.SetupService_RegisterForSetupServer
	//protoUpdateStreamDone chan bool
	cli       api.SetupServiceClient
	connected bool
}

func (p *SetupPeer) ID() pkg.NodeID {
	return p.id
}

// func (p *SetupPeer) SendUpdate(psu protocols.StatusUpdate) {
// 	apiDesc := getAPIProtocolDesc(&psu.Descriptor)
// 	err := p.protoUpdateStream.Send(&api.ProtocolUpdate{ProtocolDescriptor: apiDesc, ProtocolStatus: api.ProtocolStatus(psu.Status)})
// 	if err != nil {
// 		close(p.protocolUpdateQueue)
// 	}
// }

type ComputePeer struct {
	id                 pkg.NodeID
	circuitUpdateQueue chan circuits.Update
	cli                api.ComputeServiceClient
	connected          bool
}

func (p *ComputePeer) ID() pkg.NodeID {
	return p.id
}

type SignatureScheme struct {
	Type api.SignatureType
	sk   []byte // as generic as possible
}
