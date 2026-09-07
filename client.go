package helium

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/ChristianMct/helium/api"
	"github.com/ChristianMct/helium/api/pb"
	"github.com/ChristianMct/helium/circuits"
	"github.com/ChristianMct/helium/objectstore"
	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/services"
	"github.com/ChristianMct/helium/services/compute"
	"github.com/ChristianMct/helium/sessions"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

const (
	ClientConnectTimeout = 3 * time.Second
)

// HeliumClient is a peer node of the helper-assisted setting. It runs the node's
// protocol engine and compute service, and communicates with the helium server
// over gRPC: it receives the coordination events from the server's log, sends
// its shares and inputs to the server, and queries it for protocol outputs and
// ciphertexts.
type HeliumClient struct {
	id, helperID  sessions.NodeID
	helperAddress Address
	config        Config
	sess          *sessions.Session

	engine *protocols.MHEMPC
	*protocols.KeyProvider
	compute *compute.Service
	trans   *clientTransport

	// coordination event stream
	streamMu  sync.Mutex
	past      []Event
	protoLive chan protocols.Event
	circLive  chan circuits.Event

	*grpc.ClientConn
	rpc pb.HeliumClient
	statsHandler
}

// Dialer is a function that returns a net.Conn to the provided address.
type Dialer = func(c context.Context, addr string) (net.Conn, error)

// NewHeliumClient creates a new helium client from the provided config and node list.
// The secrets provider is called for the node's session secrets if the node is a session node.
func NewHeliumClient(config Config, nl List, secrets SecretProvider) (*HeliumClient, error) {
	if err := ValidateConfig(config, nl); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	hc := new(HeliumClient)
	hc.id = config.ID
	hc.helperID = config.HelperID
	hc.helperAddress = nl.AddressOf(config.HelperID)
	hc.config = config

	sp := config.SessionParameters[0]
	var sec *sessions.Secrets
	if slices.Contains(sp.Nodes, hc.id) {
		if secrets == nil {
			return nil, fmt.Errorf("session node %s must provide a secrets provider", hc.id)
		}
		var err error
		if sec, err = secrets(sp.ID, hc.id); err != nil {
			return nil, fmt.Errorf("cannot load secrets: %w", err)
		}
	}

	var err error
	hc.sess, err = sessions.NewSession(hc.id, sp, sec)
	if err != nil {
		return nil, fmt.Errorf("cannot create session: %w", err)
	}

	os, err := objectstore.NewObjectStoreFromConfig(config.ObjectStoreConfig)
	if err != nil {
		return nil, fmt.Errorf("cannot create object store: %w", err)
	}

	hc.trans = &clientTransport{hc: hc}

	hc.engine, err = protocols.NewMHEMPC(hc.id, hc.sess, config.ProtocolsConfig, hc.trans,
		protocols.NewObjectStoreResultBackend(os, hc.sess.ID), hc.getKeySwitchInput)
	if err != nil {
		return nil, fmt.Errorf("cannot create protocol engine: %w", err)
	}

	hc.KeyProvider = protocols.NewKeyProvider(hc.engine)

	hc.compute, err = compute.NewComputeService(hc.id, hc.sess, config.ComputeConfig, hc.engine, nil, hc.KeyProvider)
	if err != nil {
		return nil, fmt.Errorf("cannot create compute service: %w", err)
	}

	return hc, nil
}

// ID returns the node id of the client.
func (hc *HeliumClient) ID() sessions.NodeID {
	return hc.id
}

// NodeID returns the node id of the client.
func (hc *HeliumClient) NodeID() sessions.NodeID {
	return hc.id
}

// Session returns the client's session.
func (hc *HeliumClient) Session() *sessions.Session {
	return hc.sess
}

// Connect establishes a connection to the helium server.
func (hc *HeliumClient) Connect() error {
	return hc.ConnectWithDialer(func(_ context.Context, _ string) (net.Conn, error) {
		return net.Dial("tcp", hc.helperAddress.String())
	})
}

// ConnectWithDialer establishes a connection to the helium server using the provided dialer.
func (hc *HeliumClient) ConnectWithDialer(dialer Dialer) error {
	interceptors := []grpc.UnaryClientInterceptor{
		// t.clientSigner,
	}

	opts := []grpc.DialOption{
		grpc.WithContextDialer(dialer),
		grpc.WithBlock(),
		grpc.WithConnectParams(grpc.ConnectParams{Backoff: backoff.DefaultConfig, MinConnectTimeout: 1 * time.Second}),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(MaxMsgSize),
			grpc.MaxCallSendMsgSize(MaxMsgSize)),
		grpc.WithStatsHandler(&hc.statsHandler),
		grpc.WithChainUnaryInterceptor(interceptors...),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: time.Second, Timeout: time.Minute}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}

	ctx, cancel := context.WithTimeout(context.Background(), ClientConnectTimeout)
	defer cancel()
	var err error
	hc.ClientConn, err = grpc.DialContext(ctx, string(hc.helperAddress), opts...)
	if err != nil {
		return fmt.Errorf("fail establish connection to the helper at tcp://%s: %w", hc.helperAddress, err)
	}

	hc.rpc = pb.NewHeliumClient(hc.ClientConn)

	return nil
}

// Close closes the connection to the helium server.
func (hc *HeliumClient) Close() error {
	if hc.ClientConn == nil {
		return nil
	}
	return hc.ClientConn.Close()
}

// Run runs the app on the peer node: the node takes part in the setup protocols and in the
// circuits announced by the helper. The node's outputs are sent on the returned channel,
// which is closed when the helper terminates the coordination.
func (hc *HeliumClient) Run(ctx context.Context, app App, ip compute.InputProvider) (outs <-chan circuits.Output, err error) {
	if hc.rpc == nil {
		return nil, fmt.Errorf("client is not connected")
	}
	if err := hc.compute.RegisterCircuits(app.Circuits); err != nil {
		return nil, fmt.Errorf("could not register all circuits: %w", err)
	}

	ctx = hc.nodeContext(ctx)

	if err := hc.openEventStream(ctx); err != nil {
		return nil, fmt.Errorf("cannot register to the helper: %w", err)
	}

	go func() {
		if err := hc.engine.Run(ctx, hc); err != nil {
			hc.Logf("protocol engine error: %s", err)
		}
	}()

	or := make(chan circuits.Output)
	go func() {
		if err := hc.compute.Run(ctx, ip, or, &clientCircuitCoordinator{hc}, hc.trans, nil); err != nil {
			hc.Logf("compute service error: %s", err)
		}
	}()

	return or, nil
}

// EvalCircuit sends a circuit to the helium server for evaluation.
func (hc *HeliumClient) EvalCircuit(ctx context.Context, cd circuits.Descriptor) error {
	_, err := hc.rpc.EvalCircuit(hc.outgoingContext(ctx), api.GetCircuitDesc(cd))
	return err
}

// nodeContext returns a context with the node and session ids of the client.
func (hc *HeliumClient) nodeContext(ctx context.Context) context.Context {
	return sessions.NewContext(sessions.ContextWithNodeID(ctx, hc.id), hc.sess.ID)
}

// getKeySwitchInput is the protocols.KeySwitchInputProvider of the client's engine.
func (hc *HeliumClient) getKeySwitchInput(ctx context.Context, pd protocols.Descriptor) (*protocols.KeySwitchInput, error) {
	return hc.compute.GetKeySwitchInput(ctx, pd)
}

// openEventStream registers the client with the helium server, reads the past events
// and starts demultiplexing the live events into the protocol and circuit streams.
func (hc *HeliumClient) openEventStream(ctx context.Context) error {
	hc.streamMu.Lock()
	defer hc.streamMu.Unlock()
	if hc.protoLive != nil {
		return fmt.Errorf("event stream already open")
	}

	stream, err := hc.rpc.Register(hc.outgoingContext(ctx), &pb.Void{})
	if err != nil {
		return err
	}

	present, err := readPresentFromStream(stream)
	if err != nil {
		return err
	}

	hc.past = make([]Event, 0, present)
	for i := 0; i < present; i++ {
		apiEv, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("error while reading past events: %w", err)
		}
		ev, err := toNodeEvent(apiEv)
		if err != nil {
			return err
		}
		hc.past = append(hc.past, ev)
	}
	hc.Logf("registered, %d past events", present)

	hc.protoLive = make(chan protocols.Event)
	hc.circLive = make(chan circuits.Event)
	protoLive, circLive := hc.protoLive, hc.circLive
	go func() {
		defer close(protoLive)
		defer close(circLive)
		for {
			apiEv, err := stream.Recv()
			if err != nil {
				if !errors.Is(err, io.EOF) {
					hc.Logf("error on event stream: %s", err)
				}
				return
			}
			ev, err := toNodeEvent(apiEv)
			if err != nil {
				hc.Logf("invalid event on stream: %s", err)
				continue
			}
			switch {
			case ev.Protocol != nil:
				select {
				case protoLive <- *ev.Protocol:
				case <-ctx.Done():
					return
				}
			case ev.Circuit != nil:
				select {
				case circLive <- *ev.Circuit:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return nil
}

// ---- protocols.Coordinator interface (for the client's engine)

// Register implements protocols.Coordinator.
func (hc *HeliumClient) Register(_ context.Context) (past []protocols.Event, live <-chan protocols.Event, err error) {
	hc.streamMu.Lock()
	defer hc.streamMu.Unlock()
	if hc.protoLive == nil {
		return nil, nil, fmt.Errorf("event stream not open")
	}
	for _, ev := range hc.past {
		if ev.Protocol != nil {
			past = append(past, *ev.Protocol)
		}
	}
	return past, hc.protoLive, nil
}

// Publish implements protocols.Coordinator. Peer nodes never aggregate protocols in the
// helper-assisted setting, hence never publish events.
func (hc *HeliumClient) Publish(_ context.Context, ev protocols.Event) error {
	return fmt.Errorf("peer nodes cannot publish events (event: %s)", ev)
}

// clientCircuitCoordinator is the compute.Coordinator of the client's compute service.
type clientCircuitCoordinator struct {
	hc *HeliumClient
}

func (cc *clientCircuitCoordinator) Register(_ context.Context) (past []circuits.Event, live <-chan circuits.Event, err error) {
	cc.hc.streamMu.Lock()
	defer cc.hc.streamMu.Unlock()
	if cc.hc.circLive == nil {
		return nil, nil, fmt.Errorf("event stream not open")
	}
	for _, ev := range cc.hc.past {
		if ev.Circuit != nil {
			past = append(past, *ev.Circuit)
		}
	}
	return past, cc.hc.circLive, nil
}

func (cc *clientCircuitCoordinator) Publish(_ context.Context, ev circuits.Event) error {
	return fmt.Errorf("peer nodes cannot publish circuit events (event: %s)", ev)
}

// ---- transport (protocols.ShareTransport and compute.Transport over gRPC)

type clientTransport struct {
	hc *HeliumClient
}

// PutShare sends a share to the helium server.
func (ct *clientTransport) PutShare(ctx context.Context, pd protocols.Descriptor, share protocols.Share) error {
	service := "compute"
	if pd.Signature.Type.IsSetup() {
		service = "setup"
	}
	ctx = context.WithValue(ctx, services.CtxKeyName, service) // for network statistics
	apiShare, err := api.GetShare(&share)
	if err != nil {
		return err
	}
	_, err = ct.hc.rpc.PutShare(ct.hc.outgoingContext(ctx), apiShare)
	return err
}

// GetAggregationOutput queries the aggregated share of a protocol from the helium server.
func (ct *clientTransport) GetAggregationOutput(ctx context.Context, pd protocols.Descriptor) (protocols.Share, error) {
	service := "compute"
	if pd.Signature.Type.IsSetup() {
		service = "setup"
	}
	ctx = context.WithValue(ctx, services.CtxKeyName, service)
	apiOut, err := ct.hc.rpc.GetAggregationOutput(ct.hc.outgoingContext(ctx), api.GetProtocolDesc(&pd))
	if err != nil {
		return protocols.Share{}, err
	}
	return api.ToShare(apiOut.AggregatedShare)
}

// GetCiphertext queries a ciphertext from the helium server.
func (ct *clientTransport) GetCiphertext(ctx context.Context, ctID sessions.CiphertextID) (*sessions.Ciphertext, error) {
	ctx = context.WithValue(ctx, services.CtxKeyName, "compute")
	apiCt, err := ct.hc.rpc.GetCiphertext(ct.hc.outgoingContext(ctx), &pb.CiphertextID{CiphertextId: string(ctID)})
	if err != nil {
		return nil, err
	}
	return api.ToCiphertext(apiCt)
}

// PutCiphertext sends a ciphertext to the helium server.
func (ct *clientTransport) PutCiphertext(ctx context.Context, c sessions.Ciphertext) error {
	ctx = context.WithValue(ctx, services.CtxKeyName, "compute")
	apiCt, err := api.GetCiphertext(&c)
	if err != nil {
		return err
	}
	_, err = ct.hc.rpc.PutCiphertext(ct.hc.outgoingContext(ctx), apiCt)
	return err
}

func (hc *HeliumClient) outgoingContext(ctx context.Context) context.Context {
	ctx = sessions.ContextWithNodeID(ctx, hc.id)
	if _, has := sessions.IDFromContext(ctx); !has {
		ctx = sessions.NewContext(ctx, hc.sess.ID)
	}
	ctx, err := getOutgoingContext(ctx)
	if err != nil {
		panic(err)
	}
	return ctx
}

// Logf logs a message with the client's prefix.
func (hc *HeliumClient) Logf(msg string, v ...any) {
	log.Printf("%s | [HeliumClient] %s\n", hc.id, fmt.Sprintf(msg, v...))
}

func readPresentFromStream(stream grpc.ClientStream) (int, error) {
	md, err := stream.Header()
	if err != nil {
		return 0, err
	}
	vals := md.Get("present")
	if len(vals) != 1 {
		return 0, nil
	}

	present, err := strconv.Atoi(vals[0])
	if err != nil {
		return 0, fmt.Errorf("invalid stream header: bad value in present field: %s", vals[0])
	}
	return present, nil
}
