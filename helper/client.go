package helper

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

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/api/pb"
	"github.com/ChristianMct/helium/circuits"
	"github.com/ChristianMct/helium/node"
	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/utils/objectstore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// Client is a peer node of the helper-assisted setting. It runs the node's protocol
// and circuit runners, and communicates with the helper server over gRPC: it receives
// the coordination events from the server's log, sends its shares and inputs to the
// server, and queries it for protocol outputs and operands.
type Client struct {
	id, helperID  helium.NodeID
	helperAddress helium.NodeAddress
	config        Config
	sess          *helium.Session

	protocols *protocols.Runner
	*protocols.KeyProvider
	circuits *circuits.Runner
	trans    *clientTransport

	// coordination event stream
	streamMu  sync.Mutex
	past      []node.Event
	protoLive chan protocols.Event
	circLive  chan circuits.Event

	*grpc.ClientConn
	rpc pb.HeliumClient
	statsHandler
}

// Dialer is a function that returns a net.Conn to the provided address.
type Dialer = func(c context.Context, addr string) (net.Conn, error)

// NewClient creates a new helper-assisted client from the provided config and node
// list. The secrets provider is called for the node's session secrets if the node is
// a session node.
func NewClient(config Config, secrets helium.SecretProvider) (*Client, error) {
	if err := ValidateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	hc := new(Client)
	hc.id = config.ID
	hc.helperID = config.Helper.NodeID
	hc.helperAddress = config.Helper.NodeAddress
	hc.config = config

	sp := config.SessionParameters
	var sec *helium.Secrets
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
	hc.sess, err = helium.NewSession(hc.id, sp, sec)
	if err != nil {
		return nil, fmt.Errorf("cannot create session: %w", err)
	}

	os, err := objectstore.NewObjectStoreFromConfig(config.ObjectStore)
	if err != nil {
		return nil, fmt.Errorf("cannot create object store: %w", err)
	}

	hc.trans = &clientTransport{hc: hc}

	hc.protocols, err = protocols.NewRunner(hc.id, hc.sess, protocols.Config{MaxParticipation: config.MaxParticipation}, hc.trans,
		protocols.NewObjectStoreResultBackend(os, hc.sess.ID), hc.getKeySwitchInput)
	if err != nil {
		return nil, fmt.Errorf("cannot create protocol runner: %w", err)
	}

	hc.KeyProvider = protocols.NewKeyProvider(hc.protocols)

	hc.circuits, err = circuits.NewRunner(hc.id, hc.sess, circuits.Config{MaxEvaluation: config.MaxEvaluation}, hc.trans, helium.NewCachedPublicKeyBackend(hc.KeyProvider))
	if err != nil {
		return nil, fmt.Errorf("cannot create circuit runner: %w", err)
	}

	return hc, nil
}

// ID returns the node id of the client.
func (hc *Client) ID() helium.NodeID {
	return hc.id
}

// Session returns the client's session state.
func (hc *Client) Session() *helium.Session {
	return hc.sess
}

// Protocols returns the client's protocol runner.
func (hc *Client) Protocols() *protocols.Runner {
	return hc.protocols
}

// Circuits returns the client's circuit runner.
func (hc *Client) Circuits() *circuits.Runner {
	return hc.circuits
}

// Connect creates the connection to the helper server. It does not block: the
// connection is established lazily, and the failure to reach the helper is reported
// by Run, when the client opens the coordination stream.
func (hc *Client) Connect() error {
	// the helper's address is resolved and dialed by grpc.
	return hc.connect("dns:///" + string(hc.helperAddress))
}

// ConnectWithDialer creates the connection to the helper server over the provided
// dialer, for the settings in which the helper is not reached over the network (e.g.,
// an in-memory connection in tests). The helper's address is passed to the dialer
// as-is, without being resolved. Like Connect, it does not block.
func (hc *Client) ConnectWithDialer(dialer Dialer) error {
	return hc.connect("passthrough:///"+string(hc.helperAddress), grpc.WithContextDialer(dialer))
}

// connect creates the connection to the helper at the given grpc target, with the
// client's transport options and the provided extra ones.
func (hc *Client) connect(target string, extraOpts ...grpc.DialOption) error {

	// the helper is authenticated by its node id, not by the dialed address (see
	// TLSConfig.clientCredentials).
	creds := insecure.NewCredentials()
	if hc.config.TLS.InsecureChannels {
		hc.Logf("WARNING: connecting with TLS disabled, the helper is unauthenticated")
	} else {
		var err error
		if creds, err = hc.config.TLS.clientCredentials(hc.id, hc.helperID); err != nil {
			return fmt.Errorf("cannot build the client TLS credentials: %w", err)
		}
	}

	opts := []grpc.DialOption{
		grpc.WithConnectParams(grpc.ConnectParams{Backoff: backoff.DefaultConfig, MinConnectTimeout: 1 * time.Second}),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(MaxMsgSize),
			grpc.MaxCallSendMsgSize(MaxMsgSize)),
		grpc.WithStatsHandler(&hc.statsHandler),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: time.Second, Timeout: time.Minute}),
		grpc.WithTransportCredentials(creds),
	}
	opts = append(opts, extraOpts...)

	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		return fmt.Errorf("fail establish connection to the helper at tcp://%s: %w", hc.helperAddress, err)
	}

	hc.ClientConn = conn
	hc.rpc = pb.NewHeliumClient(hc.ClientConn)

	return nil
}

// Close closes the connection to the helper server.
func (hc *Client) Close() error {
	if hc.ClientConn == nil {
		return nil
	}
	return hc.ClientConn.Close()
}

// Run runs the app on the peer node: the node takes part in the setup protocols, then runs
// the app's Main function, through which it takes part in the circuits and protocols the
// application requests. The method returns once Main has returned and the helper has
// terminated the coordination, with Main's error, if any.
//
// The method starts by opening the coordination stream, waiting for the helper to become
// available if it is not yet: a node can be started before the helper. The wait is bounded
// by ctx only.
func (hc *Client) Run(ctx context.Context, app helium.App) error {
	if hc.rpc == nil {
		return fmt.Errorf("client is not connected")
	}
	if err := hc.circuits.RegisterCircuits(app.Circuits); err != nil {
		return fmt.Errorf("could not register all circuits: %w", err)
	}

	rt := node.New(hc.id, hc.sess, hc.protocols, hc.circuits, nil)

	if err := hc.openEventStream(ctx); err != nil {
		return fmt.Errorf("cannot register to the helper: %w", err)
	}

	protoCoord := rt.ProtocolCoordinator(&clientProtocolCoordinator{hc})
	circCoord := rt.CircuitCoordinator(&clientCircuitCoordinator{hc})
	var runners sync.WaitGroup
	var protoErr, circErr error
	runners.Add(2)
	go func() {
		defer runners.Done()
		if protoErr = hc.protocols.Run(ctx, protoCoord); protoErr != nil {
			hc.Logf("protocol runner error: %s", protoErr)
		}
	}()
	go func() {
		defer runners.Done()
		if circErr = hc.circuits.Run(ctx, circCoord); circErr != nil {
			hc.Logf("circuit runner error: %s", circErr)
		}
	}()

	var mainErr error
	if app.Main != nil {
		mainErr = app.Main(ctx, rt)
		hc.Logf("app main returned (err: %v)", mainErr)
	}
	rt.Finish()
	runners.Wait()

	return errors.Join(mainErr, protoErr, circErr)
}

// getKeySwitchInput is the protocols.KeySwitchInputProvider of the client's runner.
func (hc *Client) getKeySwitchInput(ctx context.Context, pd protocols.Descriptor) (*protocols.KeySwitchInput, error) {
	return hc.circuits.GetKeySwitchInput(ctx, pd)
}

// openEventStream registers the client with the helper server, reads the past events
// and starts demultiplexing the live events into the protocol and circuit streams. The
// registration is the call that waits for the connection to the helper to be
// established (see Run); the other calls fail fast when the helper is unavailable.
func (hc *Client) openEventStream(ctx context.Context) error {
	hc.streamMu.Lock()
	defer hc.streamMu.Unlock()
	if hc.protoLive != nil {
		return fmt.Errorf("event stream already open")
	}

	stream, err := hc.rpc.Register(hc.outgoingContext(ctx), &pb.Void{}, grpc.WaitForReady(true))
	if err != nil {
		return err
	}

	present, err := readPresentFromStream(stream)
	if err != nil {
		return err
	}

	hc.past = make([]node.Event, 0, present)
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

// ---- coordination streams, backed by the helper's event stream

// clientProtocolCoordinator is the protocols.Coordinator of the client's protocol runner.
type clientProtocolCoordinator struct {
	hc *Client
}

func (cc *clientProtocolCoordinator) Register(_ context.Context) (past []protocols.Event, live <-chan protocols.Event, err error) {
	cc.hc.streamMu.Lock()
	defer cc.hc.streamMu.Unlock()
	if cc.hc.protoLive == nil {
		return nil, nil, fmt.Errorf("event stream not open")
	}
	for _, ev := range cc.hc.past {
		if ev.Protocol != nil {
			past = append(past, *ev.Protocol)
		}
	}
	return past, cc.hc.protoLive, nil
}

// Publish rejects the event: peer nodes never aggregate protocols in the
// helper-assisted setting, hence never publish events.
func (cc *clientProtocolCoordinator) Publish(_ context.Context, ev protocols.Event) error {
	return fmt.Errorf("peer nodes cannot publish events (event: %s)", ev)
}

// clientCircuitCoordinator is the circuits.Coordinator of the client's circuit runner.
type clientCircuitCoordinator struct {
	hc *Client
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

// Publish rejects the event: peer nodes never evaluate circuits in the
// helper-assisted setting, hence never publish events.
func (cc *clientCircuitCoordinator) Publish(_ context.Context, ev circuits.Event) error {
	return fmt.Errorf("peer nodes cannot publish circuit events (event: %s)", ev)
}

// ---- transport (protocols.ShareTransport and circuits.OperandTransport over gRPC)

type clientTransport struct {
	hc *Client
}

// PutShare sends a share to the helper server.
func (ct *clientTransport) PutShare(ctx context.Context, pd protocols.Descriptor, share protocols.Share) error {
	service := "compute"
	if pd.Signature.Type.IsSetup() {
		service = "setup"
	}
	ctx = contextWithService(ctx, service) // for network statistics
	apiShare, err := GetShare(&share)
	if err != nil {
		return err
	}
	_, err = ct.hc.rpc.PutShare(ct.hc.outgoingContext(ctx), apiShare)
	return err
}

// GetAggregationOutput queries the aggregated share of a protocol from the helper server.
func (ct *clientTransport) GetAggregationOutput(ctx context.Context, pd protocols.Descriptor) (protocols.Share, error) {
	service := "compute"
	if pd.Signature.Type.IsSetup() {
		service = "setup"
	}
	ctx = contextWithService(ctx, service)
	apiOut, err := ct.hc.rpc.GetAggregationOutput(ct.hc.outgoingContext(ctx), GetProtocolDesc(&pd))
	if err != nil {
		return protocols.Share{}, err
	}
	return ToShare(apiOut.AggregatedShare)
}

// PutOperand sends an input operand to the helper server (the evaluator).
func (ct *clientTransport) PutOperand(ctx context.Context, _ helium.Descriptor, op helium.Operand) error {
	ctx = contextWithService(ctx, "compute")
	apiCt, err := GetOperand(&op)
	if err != nil {
		return err
	}
	_, err = ct.hc.rpc.PutCiphertext(ct.hc.outgoingContext(ctx), apiCt)
	return err
}

// GetOperand queries an operand from the helper server.
func (ct *clientTransport) GetOperand(ctx context.Context, id helium.OperandID) (*helium.Operand, error) {
	ctx = contextWithService(ctx, "compute")
	apiCt, err := ct.hc.rpc.GetCiphertext(ct.hc.outgoingContext(ctx), &pb.CiphertextID{CiphertextId: string(id)})
	if err != nil {
		return nil, err
	}
	return ToOperand(apiCt)
}

// outgoingContext tags the outgoing request with the node's id, and with the phase it
// belongs to when set (see contextWithService).
func (hc *Client) outgoingContext(ctx context.Context) context.Context {
	return outgoingContextWithNodeID(ctx, hc.id)
}

// Logf logs a message with the client's prefix.
func (hc *Client) Logf(msg string, v ...any) {
	log.Printf("%s | [helper.Client] %s\n", hc.id, fmt.Sprintf(msg, v...))
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
