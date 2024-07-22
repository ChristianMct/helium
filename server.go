package helium

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/ChristianMct/helium/api"
	"github.com/ChristianMct/helium/api/pb"
	"github.com/ChristianMct/helium/circuits"
	"github.com/ChristianMct/helium/coordinator"
	"github.com/ChristianMct/helium/node"
	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/services/compute"
	"github.com/ChristianMct/helium/services/setup"
	"github.com/ChristianMct/helium/sessions"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	MaxMsgSize       = 1024 * 1024 * 32
	KeepaliveTime    = time.Second
	KeepaliveTimeout = time.Second
)

// HeliumServer is the server-side of the helium transport.
// In the current implementation, the server is responsible for keeping the event log and
// a server cannot be restarted after it is closed. // TODO
type HeliumServer struct {
	sessions.PublicKeyProvider
	helperNode     *node.Node
	id             sessions.NodeID
	incomingShares chan protocols.Share

	// event log
	events       coordinator.Log[node.Event]
	eventsClosed bool
	//eventsMu     sync.RWMutex

	mu sync.Mutex

	nodes map[sessions.NodeID]*peer
	//nodesMu sync.RWMutex
	closing chan struct{}

	// grpc API
	*grpc.Server
	*pb.UnimplementedHeliumServer
	statsHandler
}

// NewHeliumServer creates a new helium server with the provided node information and handlers.
func NewHeliumServer(helperNode *node.Node) *HeliumServer {
	hsv := new(HeliumServer)
	hsv.helperNode = helperNode
	hsv.id = helperNode.ID()

	hsv.PublicKeyProvider = helperNode

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
			Timeout: KeepaliveTime,
		}),
	}

	hsv.Server = grpc.NewServer(serverOpts...)
	hsv.Server.RegisterService(&pb.Helium_ServiceDesc, hsv)

	hsv.nodes = make(map[sessions.NodeID]*peer)
	for _, n := range helperNode.NodeList() {
		hsv.nodes[n.NodeID] = &peer{}
	}

	hsv.incomingShares = make(chan protocols.Share)

	return hsv
}

// peer is the internal representation of a connected peer.
type peer struct {
	sendQueue chan node.Event // a queue of messages to be sent to this peer
}

type nodeCoordinator struct {
	*HeliumServer
}

func (nc *nodeCoordinator) Register(ctx context.Context) (evChan *coordinator.Channel[node.Event], present int, err error) {

	incoming := make(chan node.Event, len(nc.events))
	for _, ev := range nc.events {
		incoming <- ev
	}

	outgoing := make(chan node.Event)
	go func() {
		for ev := range outgoing {
			ev := ev
			nc.AppendEventToLog(ev)
		}
		nc.CloseEventLog()
	}()

	return &coordinator.Channel[node.Event]{Outgoing: outgoing, Incoming: incoming}, len(nc.events), nil
}

type nodeTransport struct {
	s *HeliumServer
}

func (nt *nodeTransport) IncomingShares() <-chan protocols.Share {
	return nt.s.incomingShares
}

func (nt *nodeTransport) OutgoingShares() chan<- protocols.Share {
	return nil
}

func (nt *nodeTransport) GetAggregationOutput(ctx context.Context, pd protocols.Descriptor) (*protocols.AggregationOutput, error) {
	panic("unimplemented")
}

func (nt *nodeTransport) GetCiphertext(ctx context.Context, ctID sessions.CiphertextID) (*sessions.Ciphertext, error) {
	panic("unimplemented")
}

func (nt *nodeTransport) PutCiphertext(ctx context.Context, ct sessions.Ciphertext) error {
	panic("unimplemented")
}

func (hsv *HeliumServer) Run(ctx context.Context, app node.App, ip compute.InputProvider) (cdescs chan<- circuits.Descriptor, outs <-chan circuits.Output, err error) {

	// populates a pseudo log with completed protocols
	// TODO: proper log storing and loading
	setupSigs := setup.DescriptionToSignatureList(*app.SetupDescription)
	for _, sig := range setupSigs {
		protoCompleted, err := hsv.helperNode.GetCompletedSetupDescriptor(ctx, sig)
		// TODO: error checking against a keynotfoud type of error to distinguish real failure cases from the absence of a completed descriptor
		if protoCompleted != nil && err == nil {
			pd := *protoCompleted
			if sig.Type == protocols.RKG {
				rkg1Desc := *protoCompleted
				rkg1Desc.Type = protocols.RKG1
				hsv.AppendEventToLog(
					node.Event{SetupEvent: &setup.Event{Event: protocols.Event{EventType: protocols.Started, Descriptor: rkg1Desc}}},
					node.Event{SetupEvent: &setup.Event{Event: protocols.Event{EventType: protocols.Completed, Descriptor: rkg1Desc}}},
				)
			}
			hsv.AppendEventToLog(
				node.Event{SetupEvent: &setup.Event{Event: protocols.Event{EventType: protocols.Started, Descriptor: pd}}},
				node.Event{SetupEvent: &setup.Event{Event: protocols.Event{EventType: protocols.Completed, Descriptor: pd}}},
			)
		}
	}

	return hsv.helperNode.Run(ctx, app, ip, &nodeCoordinator{hsv}, &nodeTransport{s: hsv})
}

// AppendEventToLog is called by the server side to append a new event to the log and send it to all connected peers.
func (hsv *HeliumServer) AppendEventToLog(events ...node.Event) {
	hsv.mu.Lock()
	hsv.events = append(hsv.events, events...)
	for _, event := range events {
		for nodeID, node := range hsv.nodes {
			if node.sendQueue != nil {
				select {
				case node.sendQueue <- event:
				default:
					panic(fmt.Errorf("node %s has full send queue", nodeID)) // TODO: handle this by closing stream instead
				}
			}
		}
	}
	hsv.mu.Unlock()
}

// CloseEventLog is called by the server side to close the event log and stop sending events to connected peers.
func (hsv *HeliumServer) CloseEventLog() {
	hsv.mu.Lock()
	if hsv.eventsClosed {
		panic("events already closed")
	}
	hsv.eventsClosed = true
	for _, c := range hsv.nodes {
		if c.sendQueue != nil {
			close(c.sendQueue)
		}
	}
	hsv.mu.Unlock()
}

// Register is a gRPC handler for the Register method of the Helium service.
func (hsv *HeliumServer) Register(_ *pb.Void, stream pb.Helium_RegisterServer) error {
	nodeID := senderIDFromIncomingContext(stream.Context())
	if len(nodeID) == 0 {
		return status.Error(codes.FailedPrecondition, "caller must specify node id for stream")
	}

	hsv.Logf("connected %s", nodeID)

	hsv.mu.Lock()
	present := len(hsv.events)
	pastEvents := hsv.events
	peer, has := hsv.nodes[nodeID]
	if !has {
		panic(fmt.Errorf("invalid node id: %s", nodeID))
	}
	sendQueue := make(chan node.Event, 100000)
	peer.sendQueue = sendQueue
	if hsv.eventsClosed {
		close(sendQueue)
	}
	hsv.mu.Unlock() // all events after pastEvents will go on the sendQueue

	err := hsv.helperNode.Register(nodeID)
	if err != nil {
		panic(err)
	}
	hsv.Logf("registered %s", nodeID)

	err = stream.SendHeader(metadata.MD{"present": []string{strconv.Itoa(present)}})
	if err != nil {
		panic(err)
	}

	var done bool
	for _, ev := range pastEvents {
		err := stream.Send(api.GetNodeEvent(ev))
		if err != nil {
			done = true
			hsv.Logf("error while sending past events to %s: %s", nodeID, err)
			break
		}
	}
	//hsv.Logf("done sending %d past events to %s, stream is live", present, nodeID)

	// Processes the node's sendQueue. The sendQueue channel is closed when exiting the loop
	cancelled := stream.Context().Done()
	for !done {
		select {
		// received an event to send or closed the queue
		case evt, more := <-sendQueue:
			if more {
				if err := stream.Send(api.GetNodeEvent(evt)); err != nil {
					done = true
					hsv.Logf("error on stream send for %s: %s", nodeID, err)
				}
				//hsv.Logf("sent to node %s: %v", nodeID, evt)
			} else {
				done = true
				//hsv.Logf("update queue for %s closed", nodeID)
			}

		// stream was terminated by the node or the server
		case <-cancelled:
			done = true
			hsv.Logf("stream context done for %s, err = %s", nodeID, stream.Context().Err())

		// the transport is closing
		case <-hsv.closing:
			hsv.Logf("transport closing, closing queue for %s", nodeID)
		}
	}

	hsv.mu.Lock()
	peer.sendQueue = nil
	hsv.mu.Unlock()

	err = hsv.helperNode.Unregister(nodeID)
	if err != nil {
		panic(err)
	}
	hsv.Logf("unregistered %s", nodeID)

	return nil
}

// PutShare is a gRPC handler for the PutShare method of the Helium service.
func (hsv *HeliumServer) PutShare(inctx context.Context, apiShare *pb.Share) (*pb.Void, error) {

	_, err := getContextFromIncomingContext(inctx) // TODO: can be moved has handler ?
	if err != nil {
		return nil, err
	}

	s, err := api.ToShare(apiShare)
	if err != nil {
		hsv.Logf("got an invalid share: %s", err) // TODO add details
		return nil, err
	}

	hsv.incomingShares <- s

	return &pb.Void{}, nil
}

// GetAggregationOutput is a gRPC handler for the GetAggregationOutput method of the Helium service.
func (hsv *HeliumServer) GetAggregationOutput(inctx context.Context, apipd *pb.ProtocolDescriptor) (*pb.AggregationOutput, error) {

	ctx, err := getContextFromIncomingContext(inctx) // TODO: can be moved has handler ?
	if err != nil {
		return nil, err
	}

	pd := api.ToProtocolDesc(apipd)
	out, err := hsv.helperNode.GetAggregationOutput(ctx, *pd)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "no output for protocol %s: %s", pd.HID(), err)
	}

	s, err := api.GetShare(&out.Share)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error converting share to API: %s", err)
	}
	apiOut := &pb.AggregationOutput{AggregatedShare: s}

	peerID := senderIDFromIncomingContext(ctx)
	hsv.Logf("aggregation output %s query from %s", pd.HID(), peerID)

	return apiOut, nil
}

// GetCiphertext is a gRPC handler for the GetCiphertext method of the Helium service.
func (hsv *HeliumServer) GetCiphertext(inctx context.Context, ctid *pb.CiphertextID) (*pb.Ciphertext, error) {

	ctx, err := getContextFromIncomingContext(inctx) // TODO: can be moved has handler ?
	if err != nil {
		return nil, err
	}

	ct, err := hsv.helperNode.GetCiphertext(ctx, sessions.CiphertextID(ctid.CiphertextId))
	if err != nil {
		return nil, err
	}

	apiCt, err := api.GetCiphertext(ct)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error converting ciphertext to API: %s", err)
	}

	return apiCt, nil
}

// PutCiphertext is a gRPC handler for the PutCiphertext method of the Helium service.
func (hsv *HeliumServer) PutCiphertext(inctx context.Context, apict *pb.Ciphertext) (*pb.CiphertextID, error) {
	ct, err := api.ToCiphertext(apict)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext: %w", err)
	}

	ctx, err := getContextFromIncomingContext(inctx) // TODO: can be moved has handler ?
	if err != nil {
		return nil, err
	}

	err = hsv.helperNode.PutCiphertext(ctx, *ct)
	if err != nil {
		return nil, err
	}
	return &pb.CiphertextID{CiphertextId: string(ct.ID)}, nil
}

func (hsv *HeliumServer) PutOperand(opl circuits.OperandLabel, op *circuits.Operand) error {
	return hsv.helperNode.PutOperand(opl, op)
}

func (hsv *HeliumServer) GetOperand(opl circuits.OperandLabel) (*circuits.Operand, bool) {
	return hsv.helperNode.GetOperand(opl)
}

func (hsv *HeliumServer) Logf(msg string, v ...any) {
	log.Printf("%s | [HeliumServer] %s\n", hsv.id, fmt.Sprintf(msg, v...))
}
