package helium

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/ChristianMct/helium/api"
	"github.com/ChristianMct/helium/api/pb"
	"github.com/ChristianMct/helium/circuits"
	"github.com/ChristianMct/helium/coordinator"
	"github.com/ChristianMct/helium/objectstore"
	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/sessions"
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

// HeliumServer is the helper node of the helper-assisted setting. It runs the
// protocol engine, the coordinator and the circuit engine of the helper, owns
// the node-level event log, and serves the peer nodes over gRPC.
//
// Run runs an App on the server: the setup phase, then the app's Main function
// through which the application evaluates circuits and runs protocols (see Runtime).
// In the current implementation, a server cannot be run twice.
type HeliumServer struct {
	id       sessions.NodeID
	config   Config
	nodeList List
	sess     *sessions.Session

	engine *protocols.MHEMPC
	coord  *protocols.CentralCoordinator
	*protocols.KeyProvider
	compute *circuits.Engine

	// node-level event log
	log *coordinator.Log[Event]

	// grpc API
	*grpc.Server
	*pb.UnimplementedHeliumServer
	statsHandler
}

// NewHeliumServer creates a new helium server from the provided config and node list.
func NewHeliumServer(config Config, nl List) (*HeliumServer, error) {
	if err := ValidateConfig(config, nl); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	if config.ID != config.HelperID {
		return nil, fmt.Errorf("the server must be the helper node, got id %s and helper id %s", config.ID, config.HelperID)
	}

	hsv := new(HeliumServer)
	hsv.id = config.ID
	hsv.config = config
	hsv.nodeList = nl

	var err error
	hsv.sess, err = sessions.NewSession(config.ID, config.SessionParameters[0], nil) // the helper node has no secrets
	if err != nil {
		return nil, fmt.Errorf("cannot create session: %w", err)
	}

	os, err := objectstore.NewObjectStoreFromConfig(config.ObjectStoreConfig)
	if err != nil {
		return nil, fmt.Errorf("cannot create object store: %w", err)
	}

	hsv.engine, err = protocols.NewMHEMPC(hsv.id, hsv.sess, config.ProtocolsConfig, noShareTransport{},
		protocols.NewObjectStoreResultBackend(os, hsv.sess.ID), hsv.getKeySwitchInput)
	if err != nil {
		return nil, fmt.Errorf("cannot create protocol engine: %w", err)
	}

	hsv.coord, err = protocols.NewCentralCoordinator(hsv.id, hsv.sess, config.CoordinatorConfig, hsv.engine)
	if err != nil {
		return nil, fmt.Errorf("cannot create coordinator: %w", err)
	}

	hsv.KeyProvider = protocols.NewKeyProvider(hsv.engine)

	hsv.compute, err = circuits.NewEngine(hsv.id, hsv.sess, config.CircuitsConfig, noOperandTransport{}, sessions.NewCachedPublicKeyBackend(hsv.KeyProvider))
	if err != nil {
		return nil, fmt.Errorf("cannot create compute engine: %w", err)
	}

	hsv.log = coordinator.NewLog[Event]()

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
func (hsv *HeliumServer) ID() sessions.NodeID {
	return hsv.id
}

// Session returns the server's session.
func (hsv *HeliumServer) Session() *sessions.Session {
	return hsv.sess
}

// Protocols returns the helper's protocol engine.
func (hsv *HeliumServer) Protocols() *protocols.MHEMPC {
	return hsv.engine
}

// Circuits returns the helper's circuit engine.
func (hsv *HeliumServer) Circuits() *circuits.Engine {
	return hsv.compute
}

// Run runs the app on the helper node: it registers the app's circuits, starts the
// engines, runs the setup phase described by the app and then the app's Main function,
// through which the application requests circuit evaluations and protocols. Once Main
// returns, the helper terminates the coordination (the peers' event streams end once
// all circuits and protocols are done) and Run returns Main's error, if any.
func (hsv *HeliumServer) Run(ctx context.Context, app App) error {

	if app.SetupDescription == nil {
		return fmt.Errorf("app must provide a setup description") // TODO: inference of setup description from registered circuits.
	}
	if err := hsv.compute.RegisterCircuits(app.Circuits); err != nil {
		return fmt.Errorf("could not register all circuits: %w", err)
	}

	ctx = hsv.nodeContext(ctx)
	rt := newRuntime(hsv.id, hsv.sess, hsv.engine, hsv.compute, hsv)

	// restores the completed protocols from the persistent state
	sigs := SetupDescriptionToSignatureList(*app.SetupDescription)
	restored, err := hsv.engine.RestoreCompleted(sigs...)
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

	// runs the engines on the gated coordination streams
	protoCoord := &gatedCoordinator[protocols.Event]{register: hsv.coord.Register, publish: hsv.coord.Publish, g: rt.protoGate}
	circCoord := &gatedCoordinator[circuits.Event]{register: hsv.registerCircuits, publish: hsv.publishCircuitEvent, g: rt.circGate}
	var engines sync.WaitGroup
	var protoErr, circErr error
	engines.Add(2)
	go func() {
		defer engines.Done()
		if protoErr = hsv.engine.Run(ctx, protoCoord); protoErr != nil {
			hsv.Logf("protocol engine error: %s", protoErr)
		}
	}()
	go func() {
		defer engines.Done()
		if circErr = hsv.compute.Run(ctx, circCoord); circErr != nil {
			hsv.Logf("circuit engine error: %s", circErr)
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
	rt.finish()

	// terminates the coordination: waits for the running circuits to complete, then closes
	// the coordinator, which closes the event log once all protocols are done
	closeErr := hsv.compute.AwaitIdle(ctx)
	hsv.coord.Close()
	engines.Wait()

	return errors.Join(mainErr, closeErr, protoErr, circErr)
}

// startCircuit implements starter: it appends the Started event of the circuit to the log.
func (hsv *HeliumServer) startCircuit(_ context.Context, cd circuits.Descriptor) error {
	if err := hsv.compute.Validate(cd); err != nil {
		return err
	}
	ev := circuits.Event{EventType: circuits.Started, Descriptor: cd}
	return hsv.log.Append(Event{Circuit: &ev})
}

// startProtocol implements starter: it requests the execution of the protocol to the coordinator.
func (hsv *HeliumServer) startProtocol(ctx context.Context, sig protocols.Signature) error {
	return hsv.coord.RunSignature(ctx, sig)
}

// nodeContext returns a context with the node and session ids of the server.
func (hsv *HeliumServer) nodeContext(ctx context.Context) context.Context {
	return sessions.NewContext(sessions.ContextWithNodeID(ctx, hsv.id), hsv.sess.ID)
}

func (hsv *HeliumServer) appendProtocolEvents(evs ...protocols.Event) {
	for i := range evs {
		ev := evs[i]
		if err := hsv.log.Append(Event{Protocol: &ev}); err != nil {
			hsv.Logf("cannot append %s to log: %s", ev, err)
		}
	}
}

// getKeySwitchInput is the protocols.KeySwitchInputProvider of the helper's engine.
func (hsv *HeliumServer) getKeySwitchInput(ctx context.Context, pd protocols.Descriptor) (*protocols.KeySwitchInput, error) {
	return hsv.compute.GetKeySwitchInput(ctx, pd)
}

// Log returns a copy of the node-level event log.
func (hsv *HeliumServer) Log() []Event {
	return hsv.log.Events()
}

// registerCircuits is the register function of the helper's circuit coordinator, backed
// by the node-level log.
func (hsv *HeliumServer) registerCircuits(ctx context.Context) (past []circuits.Event, live <-chan circuits.Event, err error) {
	p, l := hsv.log.Register(ctx)
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

// publishCircuitEvent is the publish function of the helper's circuit coordinator.
func (hsv *HeliumServer) publishCircuitEvent(_ context.Context, ev circuits.Event) error {
	return hsv.log.Append(Event{Circuit: &ev})
}

// noShareTransport is the protocols.ShareTransport of the helper's engine: the helper
// aggregates all protocols and never sends shares nor queries outputs.
type noShareTransport struct{}

func (noShareTransport) PutShare(_ context.Context, pd protocols.Descriptor, _ protocols.Share) error {
	return fmt.Errorf("the helper node does not send shares (protocol %s)", pd.HID())
}

func (noShareTransport) GetAggregationOutput(_ context.Context, pd protocols.Descriptor) (protocols.Share, error) {
	return protocols.Share{}, fmt.Errorf("the helper node does not query aggregation outputs (protocol %s)", pd.HID())
}

// noOperandTransport is the circuits.OperandTransport of the helper's engine: the helper
// evaluates all circuits and never sends inputs nor queries operands.
type noOperandTransport struct{}

func (noOperandTransport) PutOperand(_ context.Context, cd circuits.Descriptor, _ circuits.Operand) error {
	return fmt.Errorf("the helper node does not send inputs (circuit %s)", cd.HID())
}

func (noOperandTransport) GetOperand(_ context.Context, id circuits.OperandID) (*circuits.Operand, error) {
	return nil, fmt.Errorf("the helper node does not query operands (operand %s)", id)
}

// ---- gRPC API

// Register is a gRPC handler for the Register method of the Helium service. It streams the
// node-level event log to the peer, and tracks the peer's connection for the coordinator.
func (hsv *HeliumServer) Register(_ *pb.Void, stream pb.Helium_RegisterServer) error {
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

	send := func(ev Event) error {
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
func (hsv *HeliumServer) PutShare(inctx context.Context, apiShare *pb.Share) (*pb.Void, error) {

	ctx, err := getContextFromIncomingContext(inctx)
	if err != nil {
		return nil, err
	}

	s, err := api.ToShare(apiShare)
	if err != nil {
		hsv.Logf("got an invalid share: %s", err)
		return nil, status.Errorf(codes.InvalidArgument, "invalid share: %s", err)
	}

	if err := hsv.engine.HandleShare(ctx, s); err != nil {
		hsv.Logf("rejected share from %s: %s", senderIDFromIncomingContext(inctx), err)
		return nil, status.Errorf(codes.FailedPrecondition, "share rejected: %s", err)
	}

	return &pb.Void{}, nil
}

// GetAggregationOutput is a gRPC handler for the GetAggregationOutput method of the Helium service.
func (hsv *HeliumServer) GetAggregationOutput(inctx context.Context, apipd *pb.ProtocolDescriptor) (*pb.AggregationOutput, error) {

	ctx, err := getContextFromIncomingContext(inctx)
	if err != nil {
		return nil, err
	}

	pd := api.ToProtocolDesc(apipd)
	out, err := hsv.engine.GetAggregationOutput(ctx, *pd)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "no output for protocol %s: %s", pd.HID(), err)
	}

	s, err := api.GetShare(&out.Share)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error converting share to API: %s", err)
	}

	hsv.Logf("aggregation output %s query from %s", pd.HID(), senderIDFromIncomingContext(inctx))

	return &pb.AggregationOutput{AggregatedShare: s}, nil
}

// GetCiphertext is a gRPC handler for the GetCiphertext method of the Helium service.
// It returns the operand with the requested id.
func (hsv *HeliumServer) GetCiphertext(inctx context.Context, ctid *pb.CiphertextID) (*pb.Ciphertext, error) {

	ctx, err := getContextFromIncomingContext(inctx)
	if err != nil {
		return nil, err
	}

	op, err := hsv.compute.GetOperand(ctx, circuits.OperandID(ctid.CiphertextId))
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "%s", err)
	}

	apiCt, err := api.GetOperand(op)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error converting operand to API: %s", err)
	}

	return apiCt, nil
}

// PutCiphertext is a gRPC handler for the PutCiphertext method of the Helium service.
// It delivers an input operand to the compute engine.
func (hsv *HeliumServer) PutCiphertext(inctx context.Context, apict *pb.Ciphertext) (*pb.CiphertextID, error) {
	op, err := api.ToOperand(apict)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid operand: %s", err)
	}

	ctx, err := getContextFromIncomingContext(inctx)
	if err != nil {
		return nil, err
	}

	if err := hsv.compute.HandleOperand(ctx, *op); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%s", err)
	}
	return &pb.CiphertextID{CiphertextId: string(op.ID)}, nil
}

// Logf logs a message with the server's prefix.
func (hsv *HeliumServer) Logf(msg string, v ...any) {
	log.Printf("%s | [HeliumServer] %s\n", hsv.id, fmt.Sprintf(msg, v...))
}
