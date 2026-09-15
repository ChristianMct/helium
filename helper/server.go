package helper

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/api/pb"
	"github.com/ChristianMct/helium/circuits"
	"github.com/ChristianMct/helium/node"
	"github.com/ChristianMct/helium/objectstore"
	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/utils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	MaxMsgSize       = 1024 * 1024 * 32
	KeepaliveTime    = time.Second
	KeepaliveTimeout = 5 * time.Second
)

// Server is the helper node of the helper-assisted setting. It runs the protocol
// runner, the coordinator and the circuit runner of the helper, owns the node-level
// event log, and serves the peer nodes over gRPC.
//
// Run runs an application on the server: the setup phase, then the app's Main
// function through which the application evaluates circuits and runs protocols
// (see helium.Runtime). In the current implementation, a server cannot be run twice.
type Server struct {
	id       helium.NodeID
	config   Config
	nodeList helium.NodeList
	sess     *helium.Session

	protocols *protocols.Runner
	coord     *protocols.CentralCoordinator
	*protocols.KeyProvider
	circuits *circuits.Runner

	// node-level event log
	log *helium.Log[node.Event]

	// grpc API
	*grpc.Server
	*pb.UnimplementedHeliumServer
	statsHandler
}

var _ node.Starter = (*Server)(nil)

// NewServer creates a new helper server from the provided config and node list.
func NewServer(config Config, nl helium.NodeList) (*Server, error) {
	if err := ValidateConfig(config, nl); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	if config.ID != config.HelperID {
		return nil, fmt.Errorf("the server must be the helper node, got id %s and helper id %s", config.ID, config.HelperID)
	}

	hsv := new(Server)
	hsv.id = config.ID
	hsv.config = config
	hsv.nodeList = nl

	var err error
	hsv.sess, err = helium.NewSession(config.ID, config.SessionParameters, nil) // the helper node has no secrets
	if err != nil {
		return nil, fmt.Errorf("cannot create session: %w", err)
	}

	os, err := objectstore.NewObjectStoreFromConfig(config.ObjectStore)
	if err != nil {
		return nil, fmt.Errorf("cannot create object store: %w", err)
	}

	hsv.protocols, err = protocols.NewRunner(hsv.id, hsv.sess, protocols.Config{MaxParticipation: config.MaxParticipation}, noShareTransport{},
		protocols.NewObjectStoreResultBackend(os, hsv.sess.ID), hsv.getKeySwitchInput)
	if err != nil {
		return nil, fmt.Errorf("cannot create protocol runner: %w", err)
	}

	hsv.coord, err = protocols.NewCentralCoordinator(hsv.id, hsv.sess, protocols.CoordinatorConfig{MaxProtoPerNode: config.MaxProtoPerNode}, hsv.protocols)
	if err != nil {
		return nil, fmt.Errorf("cannot create coordinator: %w", err)
	}

	hsv.KeyProvider = protocols.NewKeyProvider(hsv.protocols)

	hsv.circuits, err = circuits.NewRunner(hsv.id, hsv.sess, circuits.Config{MaxEvaluation: config.MaxEvaluation}, noOperandTransport{}, helium.NewCachedPublicKeyBackend(hsv.KeyProvider))
	if err != nil {
		return nil, fmt.Errorf("cannot create circuit runner: %w", err)
	}

	hsv.log = helium.NewLog[node.Event]()

	interceptors := []grpc.UnaryServerInterceptor{
		// t.serverSigChecker,
	}

	serverOpts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(MaxMsgSize),
		grpc.MaxSendMsgSize(MaxMsgSize),
		grpc.StatsHandler(&hsv.statsHandler),
		grpc.ChainUnaryInterceptor(interceptors...),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    KeepaliveTime,
			Timeout: KeepaliveTimeout,
		}),
	}

	hsv.Server = grpc.NewServer(serverOpts...)
	hsv.Server.RegisterService(&pb.Helium_ServiceDesc, hsv)

	return hsv, nil
}

// ID returns the node id of the server.
func (hsv *Server) ID() helium.NodeID {
	return hsv.id
}

// Session returns the server's session state.
func (hsv *Server) Session() *helium.Session {
	return hsv.sess
}

// Protocols returns the helper's protocol runner.
func (hsv *Server) Protocols() *protocols.Runner {
	return hsv.protocols
}

// Circuits returns the helper's circuit runner.
func (hsv *Server) Circuits() *circuits.Runner {
	return hsv.circuits
}

// Run runs the app on the helper node: it registers the app's circuits, starts the
// runners, runs the setup phase described by the app and then the app's Main function,
// through which the application requests circuit evaluations and protocols. Once Main
// returns, the helper terminates the coordination (the peers' event streams end once
// all circuits and protocols are done) and Run returns Main's error, if any.
func (hsv *Server) Run(ctx context.Context, app helium.App) error {

	if app.Setup == nil {
		return fmt.Errorf("app must provide a setup description") // TODO: inference of setup description from registered circuits.
	}
	if err := hsv.circuits.RegisterCircuits(app.Circuits); err != nil {
		return fmt.Errorf("could not register all circuits: %w", err)
	}

	rt := node.New(hsv.id, hsv.sess, hsv.protocols, hsv.circuits, hsv)

	// restores the completed protocols from the persistent state
	sigs := node.SetupSignatures(*app.Setup)
	restored, err := hsv.protocols.RestoreCompleted(sigs...)
	if err != nil {
		return fmt.Errorf("cannot restore completed protocols: %w", err)
	}
	hsv.coord.Restore(restored...)
	restoredSigs := utils.NewEmptySet[string]()
	for _, pd := range restored {
		restoredSigs.Add(pd.Signature.String())
	}

	// forwards the protocol events to the node-level log
	past, live, err := hsv.coord.Register(ctx)
	if err != nil {
		return fmt.Errorf("cannot register to coordinator: %w", err)
	}
	hsv.appendProtocolEvents(past...)
	go func() {
		for ev := range live {
			hsv.appendProtocolEvents(ev)
		}
		hsv.log.Close()
		hsv.Logf("event log closed")
	}()

	// runs the runners on the gated coordination streams
	protoCoord := rt.ProtocolCoordinator(hsv.coord)
	circCoord := rt.CircuitCoordinator(&serverCircuitCoordinator{hsv})
	var runners sync.WaitGroup
	var protoErr, circErr error
	runners.Add(2)
	go func() {
		defer runners.Done()
		if protoErr = hsv.protocols.Run(ctx, protoCoord); protoErr != nil {
			hsv.Logf("protocol runner error: %s", protoErr)
		}
	}()
	go func() {
		defer runners.Done()
		if circErr = hsv.circuits.Run(ctx, circCoord); circErr != nil {
			hsv.Logf("circuit runner error: %s", circErr)
		}
	}()

	// runs the setup phase
	nRun := 0
	for _, sig := range sigs {
		if restoredSigs.Contains(sig.String()) {
			continue
		}
		if err := hsv.coord.RunSignature(ctx, sig); err != nil {
			return fmt.Errorf("cannot run setup signature %s: %w", sig, err)
		}
		nRun++
	}
	hsv.Logf("running setup phase: %d signatures restored, %d to run", len(restored), nRun)

	// runs the application
	var mainErr error
	if app.Main != nil {
		mainErr = app.Main(ctx, rt)
		hsv.Logf("app main returned (err: %v)", mainErr)
	}
	rt.Finish()

	// terminates the coordination: waits for the running circuits to complete, then closes
	// the coordinator, which closes the event log once all protocols are done
	closeErr := hsv.circuits.AwaitIdle(ctx)
	hsv.coord.Close()
	runners.Wait()

	return errors.Join(mainErr, closeErr, protoErr, circErr)
}

// StartCircuit implements node.Starter: it appends the Started event of the circuit to the log.
func (hsv *Server) StartCircuit(_ context.Context, cd helium.Descriptor) error {
	if err := hsv.circuits.Validate(cd); err != nil {
		return err
	}
	ev := circuits.Event{EventType: circuits.Started, Descriptor: cd}
	return hsv.log.Append(node.Event{Circuit: &ev})
}

// StartProtocol implements node.Starter: it requests the execution of the protocol to the coordinator.
func (hsv *Server) StartProtocol(ctx context.Context, sig protocols.Signature) error {
	return hsv.coord.RunSignature(ctx, sig)
}

func (hsv *Server) appendProtocolEvents(evs ...protocols.Event) {
	for i := range evs {
		ev := evs[i]
		if err := hsv.log.Append(node.Event{Protocol: &ev}); err != nil {
			hsv.Logf("cannot append %s to log: %s", ev, err)
		}
	}
}

// getKeySwitchInput is the protocols.KeySwitchInputProvider of the helper's runner.
func (hsv *Server) getKeySwitchInput(ctx context.Context, pd protocols.Descriptor) (*protocols.KeySwitchInput, error) {
	return hsv.circuits.GetKeySwitchInput(ctx, pd)
}

// Log returns a copy of the node-level event log.
func (hsv *Server) Log() []node.Event {
	return hsv.log.Events()
}

// serverCircuitCoordinator is the circuits.Coordinator of the helper's circuit runner,
// backed by the node-level log.
type serverCircuitCoordinator struct {
	hsv *Server
}

func (sc *serverCircuitCoordinator) Register(ctx context.Context) (past []circuits.Event, live <-chan circuits.Event, err error) {
	p, l := sc.hsv.log.Register(ctx)
	for _, ev := range p {
		if ev.Circuit != nil {
			past = append(past, *ev.Circuit)
		}
	}
	ch := make(chan circuits.Event)
	go func() {
		defer close(ch)
		for ev := range l {
			if ev.Circuit == nil {
				continue
			}
			select {
			case ch <- *ev.Circuit:
			case <-ctx.Done():
				return
			}
		}
	}()
	return past, ch, nil
}

func (sc *serverCircuitCoordinator) Publish(_ context.Context, ev circuits.Event) error {
	return sc.hsv.log.Append(node.Event{Circuit: &ev})
}

// noShareTransport is the protocols.ShareTransport of the helper's runner: the helper
// aggregates all protocols and never sends shares nor queries outputs.
type noShareTransport struct{}

func (noShareTransport) PutShare(_ context.Context, pd protocols.Descriptor, _ protocols.Share) error {
	return fmt.Errorf("the helper node does not send shares (protocol %s)", pd.HID())
}

func (noShareTransport) GetAggregationOutput(_ context.Context, pd protocols.Descriptor) (protocols.Share, error) {
	return protocols.Share{}, fmt.Errorf("the helper node does not query aggregation outputs (protocol %s)", pd.HID())
}

// noOperandTransport is the circuits.OperandTransport of the helper's runner: the helper
// evaluates all circuits and never sends inputs nor queries operands.
type noOperandTransport struct{}

func (noOperandTransport) PutOperand(_ context.Context, cd helium.Descriptor, _ helium.Operand) error {
	return fmt.Errorf("the helper node does not send inputs (circuit %s)", cd.HID())
}

func (noOperandTransport) GetOperand(_ context.Context, id helium.OperandID) (*helium.Operand, error) {
	return nil, fmt.Errorf("the helper node does not query operands (operand %s)", id)
}

// ---- gRPC API

// Register is a gRPC handler for the Register method of the Helium service. It streams the
// node-level event log to the peer, and tracks the peer's connection for the coordinator.
func (hsv *Server) Register(_ *pb.Void, stream pb.Helium_RegisterServer) error {
	ctx := stream.Context()
	nodeID := senderIDFromIncomingContext(ctx)
	if len(nodeID) == 0 {
		return status.Error(codes.FailedPrecondition, "caller must specify node id for stream")
	}
	if !hsv.nodeList.Contains(nodeID) {
		return status.Errorf(codes.PermissionDenied, "unknown node id: %s", nodeID)
	}

	hsv.Logf("connected %s", nodeID)

	past, live := hsv.log.Register(ctx)

	if err := stream.SendHeader(metadata.MD{"present": []string{strconv.Itoa(len(past))}}); err != nil {
		return err
	}

	hsv.coord.PeerConnected(nodeID)
	defer func() {
		hsv.coord.PeerDisconnected(nodeID)
		hsv.Logf("disconnected %s", nodeID)
	}()

	send := func(ev node.Event) error {
		apiEv, err := getNodeEvent(ev)
		if err != nil {
			return err
		}
		return stream.Send(apiEv)
	}

	for _, ev := range past {
		if err := send(ev); err != nil {
			hsv.Logf("error while sending past events to %s: %s", nodeID, err)
			return err
		}
	}

	for ev := range live {
		if err := send(ev); err != nil {
			hsv.Logf("error on stream send for %s: %s", nodeID, err)
			return err
		}
	}

	return nil
}

// PutShare is a gRPC handler for the PutShare method of the Helium service.
func (hsv *Server) PutShare(ctx context.Context, apiShare *pb.Share) (*pb.Void, error) {

	s, err := ToShare(apiShare)
	if err != nil {
		hsv.Logf("got an invalid share: %s", err)
		return nil, status.Errorf(codes.InvalidArgument, "invalid share: %s", err)
	}

	if err := hsv.protocols.HandleShare(ctx, s); err != nil {
		hsv.Logf("rejected share from %s: %s", senderIDFromIncomingContext(ctx), err)
		return nil, status.Errorf(codes.FailedPrecondition, "share rejected: %s", err)
	}

	return &pb.Void{}, nil
}

// GetAggregationOutput is a gRPC handler for the GetAggregationOutput method of the Helium service.
func (hsv *Server) GetAggregationOutput(ctx context.Context, apipd *pb.ProtocolDescriptor) (*pb.AggregationOutput, error) {

	pd := ToProtocolDesc(apipd)
	out, err := hsv.protocols.GetAggregationOutput(ctx, *pd)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "no output for protocol %s: %s", pd.HID(), err)
	}

	s, err := GetShare(&out.Share)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error converting share to API: %s", err)
	}

	hsv.Logf("aggregation output %s query from %s", pd.HID(), senderIDFromIncomingContext(ctx))

	return &pb.AggregationOutput{AggregatedShare: s}, nil
}

// GetCiphertext is a gRPC handler for the GetCiphertext method of the Helium service.
// It returns the operand with the requested id.
func (hsv *Server) GetCiphertext(ctx context.Context, ctid *pb.CiphertextID) (*pb.Ciphertext, error) {

	op, err := hsv.circuits.GetOperand(ctx, helium.OperandID(ctid.CiphertextId))
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "%s", err)
	}

	apiCt, err := GetOperand(op)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error converting operand to API: %s", err)
	}

	return apiCt, nil
}

// PutCiphertext is a gRPC handler for the PutCiphertext method of the Helium service.
// It delivers an input operand to the circuit runner.
func (hsv *Server) PutCiphertext(ctx context.Context, apict *pb.Ciphertext) (*pb.CiphertextID, error) {
	op, err := ToOperand(apict)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid operand: %s", err)
	}

	if err := hsv.circuits.HandleOperand(ctx, *op); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%s", err)
	}
	return &pb.CiphertextID{CiphertextId: string(op.ID)}, nil
}

// Logf logs a message with the server's prefix.
func (hsv *Server) Logf(msg string, v ...any) {
	log.Printf("%s | [helper.Server] %s\n", hsv.id, fmt.Sprintf(msg, v...))
}
