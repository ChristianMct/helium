package centralized

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/circuit"
	"github.com/ChristianMct/helium/coordinator"
	"github.com/ChristianMct/helium/node"
	"github.com/ChristianMct/helium/protocol"
	"github.com/ChristianMct/helium/services/compute"
	"github.com/ChristianMct/helium/session"
	"github.com/ChristianMct/helium/transport/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
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
	session.PublicKeyProvider
	helperNode     *node.Node
	id             session.NodeID
	incomingShares chan protocol.Share

	// event log
	events       coordinator.Log[node.Event]
	eventsClosed bool
	eventsMu     sync.RWMutex

	nodes   map[session.NodeID]*peer
	nodesMu sync.RWMutex
	closing chan struct{}

	// grpc API
	*grpc.Server
	*pb.UnimplementedHeliumServer
	statsHandler
}

func RunHeliumServer(ctx context.Context, config node.Config, nl helium.NodesList, app node.App, ip compute.InputProvider) (cdescs chan<- circuit.Descriptor, outs <-chan circuit.Output, err error) {

	helperNode, err := node.New(config, nl)
	if err != nil {
		return nil, nil, err
	}

	hsv := NewHeliumServer(helperNode)

	lis, err := net.Listen("tcp", string(config.Address))
	if err != nil {
		return nil, nil, err
	}

	go hsv.Serve(lis)

	return hsv.Run(ctx, app, ip)
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
		// grpc.KeepaliveParams(keepalive.ServerParameters{
		// 	Time:    KeepaliveTime,
		// 	Timeout: KeepaliveTime,
		// }),
	}

	hsv.Server = grpc.NewServer(serverOpts...)
	hsv.Server.RegisterService(&pb.Helium_ServiceDesc, hsv)

	hsv.nodes = make(map[session.NodeID]*peer)
	for _, n := range helperNode.NodeList() {
		hsv.nodes[n.NodeID] = &peer{}
	}

	hsv.incomingShares = make(chan protocol.Share)

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
	outgoing := make(chan node.Event)

	go func() {
		for ev := range outgoing {
			ev := ev
			nc.AppendEventToLog(ev)
		}
		nc.CloseEventLog()
	}()

	return &coordinator.Channel[node.Event]{Outgoing: outgoing}, 0, nil
}

type nodeTransport struct {
	s *HeliumServer
}

func (nt *nodeTransport) IncomingShares() <-chan protocol.Share {
	return nt.s.incomingShares
}

func (nt *nodeTransport) OutgoingShares() chan<- protocol.Share {
	return nil
}

func (nt *nodeTransport) GetAggregationOutput(ctx context.Context, pd protocol.Descriptor) (*protocol.AggregationOutput, error) {
	panic("unimplemented")
}

func (nt *nodeTransport) GetCiphertext(ctx context.Context, ctID session.CiphertextID) (*session.Ciphertext, error) {
	panic("unimplemented")
}

func (nt *nodeTransport) PutCiphertext(ctx context.Context, ct session.Ciphertext) error {
	panic("unimplemented")
}

func (hsv *HeliumServer) Run(ctx context.Context, app node.App, ip compute.InputProvider) (cdescs chan<- circuit.Descriptor, outs <-chan circuit.Output, err error) {

	return hsv.helperNode.Run(ctx, app, ip, &nodeCoordinator{hsv}, &nodeTransport{s: hsv})
}

// AppendEventToLog is called by the server side to append a new event to the log and send it to all connected peers.
func (hsv *HeliumServer) AppendEventToLog(event node.Event) error {
	hsv.eventsMu.Lock()
	hsv.events = append(hsv.events, event)

	hsv.nodesMu.RLock()
	for nodeID, node := range hsv.nodes {
		if node.sendQueue != nil {
			select {
			case node.sendQueue <- event:
			default:
				panic(fmt.Errorf("node %s has full send queue", nodeID)) // TODO: handle this by closing stream instead
			}
		}
	}
	hsv.nodesMu.RUnlock()
	hsv.eventsMu.Unlock()
	return nil
}

// CloseEventLog is called by the server side to close the event log and stop sending events to connected peers.
func (hsv *HeliumServer) CloseEventLog() {
	hsv.eventsMu.Lock()
	if hsv.eventsClosed {
		panic("events already closed")
	}
	hsv.nodesMu.Lock()
	hsv.eventsClosed = true
	for _, c := range hsv.nodes {
		if c.sendQueue != nil {
			close(c.sendQueue)
		}
	}
	hsv.nodesMu.Unlock()
	hsv.eventsMu.Unlock()
}

// Register is a gRPC handler for the Register method of the Helium service.
func (hsv *HeliumServer) Register(_ *pb.Void, stream pb.Helium_RegisterServer) error {
	nodeID := senderIDFromIncomingContext(stream.Context())
	if len(nodeID) == 0 {
		return status.Error(codes.FailedPrecondition, "caller must specify node id for stream")
	}

	hsv.Logf("connected %s", nodeID)

	hsv.eventsMu.RLock()
	present := len(hsv.events)
	pastEvents := hsv.events
	hsv.nodesMu.Lock()
	peer, has := hsv.nodes[nodeID]
	if !has {
		panic(fmt.Errorf("invalid node id: %s", nodeID))
	}
	sendQueue := make(chan node.Event, 100)
	peer.sendQueue = sendQueue
	if hsv.eventsClosed {
		close(sendQueue)
	}
	hsv.nodesMu.Unlock()
	hsv.eventsMu.RUnlock() // all events after pastEvents will go on the sendQueue

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
		err := stream.Send(getAPINodeEvent(ev))
		if err != nil {
			done = true
			hsv.Logf("error while sending past events to %s: %s", nodeID, err)
			break
		}
	}
	hsv.Logf("done sending past events to %s, stream is live", nodeID)

	// Processes the node's sendQueue. The sendQueue channel is closed when exiting the loop
	cancelled := stream.Context().Done()
	for !done {
		select {
		// received an event to send or closed the queue
		case evt, more := <-sendQueue:
			if more {
				if err := stream.Send(getAPINodeEvent(evt)); err != nil {
					done = true
					hsv.Logf("error on stream send for %s: %s", nodeID, err)
				}
			} else {
				done = true
				hsv.Logf("update queue for %s closed", nodeID)
			}

		// stream was terminated by the node or the server
		case <-cancelled:
			done = true
			close(sendQueue)
			hsv.Logf("stream context done for %s, err = %s", nodeID, stream.Context().Err())

		// the transport is closing
		case <-hsv.closing:
			close(sendQueue)
			hsv.Logf("transport closing, closing queue for %s", nodeID)
		}
	}

	hsv.nodesMu.Lock()
	peer.sendQueue = nil
	hsv.nodesMu.Unlock()

	err = hsv.helperNode.Unregister(nodeID)
	if err != nil {
		panic(err)
	}

	return nil
}

// PutShare is a gRPC handler for the PutShare method of the Helium service.
func (hsv *HeliumServer) PutShare(inctx context.Context, apiShare *pb.Share) (*pb.Void, error) {

	_, err := getContextFromIncomingContext(inctx) // TODO: can be moved has handler ?
	if err != nil {
		return nil, err
	}

	s, err := getShareFromAPI(apiShare)
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

	pd := getProtocolDescFromAPI(apipd)
	out, err := hsv.helperNode.GetAggregationOutput(ctx, *pd)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "no output for protocol %s: %s", pd.HID(), err)
	}

	s, err := getAPIShare(&out.Share)
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

	ct, err := hsv.helperNode.GetCiphertext(ctx, session.CiphertextID(ctid.CiphertextId))
	if err != nil {
		return nil, err
	}

	apiCt, err := getAPICiphertext(ct)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error converting ciphertext to API: %s", err)
	}

	return apiCt, nil
}

// PutCiphertext is a gRPC handler for the PutCiphertext method of the Helium service.
func (hsv *HeliumServer) PutCiphertext(inctx context.Context, apict *pb.Ciphertext) (*pb.CiphertextID, error) {
	ct, err := getCiphertextFromAPI(apict)
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

func (hsv *HeliumServer) Logf(msg string, v ...any) {
	log.Printf("%s | [HeliumServer] %s\n", hsv.id, fmt.Sprintf(msg, v...))
}
