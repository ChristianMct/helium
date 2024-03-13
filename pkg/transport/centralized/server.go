package centralized

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/ldsec/helium/pkg"
	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/coordinator"
	"github.com/ldsec/helium/pkg/protocols"
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

// NodeWatcher is an interface for the helium server to notify registered watchers
// when a new peer is registered or unregistered. See HeliumServer.RegisterWatcher.
type NodeWatcher interface {
	// Register is called by the transport when a new peer register itself for the setup.
	Register(pkg.NodeID) error

	// Unregister is called by the transport when a peer is unregistered from the setup.
	Unregister(pkg.NodeID) error
}

// ProtocolHandler is an interface for the helium server to handle protocol-related requests from
// its peers. The interface implementation is provided by the NewHeliumServer method, and the
// created server makes calls to the interface methods when handling requests from its peers.
type ProtocolHandler interface {
	PutShare(context.Context, protocols.Share) error
	GetAggregationOutput(context.Context, protocols.Descriptor) (*protocols.AggregationOutput, error)
}

// CiphertextHandler is an interface for the helium server to handle ciphertext-related requests from
// its peers. The interface implementation is provided by the NewHeliumServer method, and the
// created server makes calls to the interface methods when handling requests from its peers.
type CiphertextHandler interface {
	GetCiphertext(context.Context, pkg.CiphertextID) (*pkg.Ciphertext, error)
	PutCiphertext(context.Context, pkg.Ciphertext) error
}

// HeliumServer is the server-side of the helium transport.
// In the current implementation, the server is responsible for keeping the event log and
// a server cannot be restarted after it is closed. // TODO
type HeliumServer struct {
	id pkg.NodeID

	// event log
	events       coordinator.Log
	eventsClosed bool
	eventsMu     sync.RWMutex

	nodes      map[pkg.NodeID]*peer
	nodesMu    sync.RWMutex
	closing    chan struct{}
	watchersMu sync.RWMutex
	watchers   []NodeWatcher

	// service API
	protocolHandler   ProtocolHandler
	ciphertextHandler CiphertextHandler

	// grpc API
	*grpc.Server
	*api.UnimplementedHeliumServer
	statsHandler
}

// NewHeliumServer creates a new helium server with the provided node information and handlers.
func NewHeliumServer(id pkg.NodeID, na pkg.NodeAddress, nl pkg.NodesList, protoHandler ProtocolHandler, ctxtHandler CiphertextHandler) *HeliumServer {
	hsv := new(HeliumServer)
	hsv.id = id

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
	hsv.Server.RegisterService(&api.Helium_ServiceDesc, hsv)

	hsv.protocolHandler = protoHandler
	hsv.ciphertextHandler = ctxtHandler

	hsv.watchers = make([]NodeWatcher, 0)

	hsv.nodes = make(map[pkg.NodeID]*peer)
	for _, n := range nl {
		hsv.nodes[n.NodeID] = &peer{}
	}

	return hsv
}

// peer is the internal representation of a connected peer.
type peer struct {
	sendQueue chan coordinator.Event // a queue of messages to be sent to this peer
}

// AppendEventToLog is called by the server side to append a new event to the log and send it to all connected peers.
func (hsv *HeliumServer) AppendEventToLog(event coordinator.Event) error {
	hsv.eventsMu.Lock()
	hsv.events = append(hsv.events, event)

	hsv.nodesMu.RLock()
	for nodeId, node := range hsv.nodes {
		if node.sendQueue != nil {
			select {
			case node.sendQueue <- event:
			default:
				panic(fmt.Errorf("node %s has full send queue", nodeId)) // TODO: handle this by closing stream instead
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

// RegisterWatcher adds a new watcher to the server. The watcher will be notified when a new peer is registered
func (hsv *HeliumServer) RegisterWatcher(nw NodeWatcher) {
	hsv.watchersMu.Lock()
	defer hsv.watchersMu.Unlock()
	hsv.watchers = append(hsv.watchers, nw)
}

// NotifyRegister notifies all registered watchers that a new peer has registered.
func (hsv *HeliumServer) NotifyRegister(node pkg.NodeID) (err error) {
	hsv.watchersMu.RLock()
	defer hsv.watchersMu.RUnlock()
	for _, w := range hsv.watchers {
		err = errors.Join(w.Register(node))
	}
	return err
}

// NotifyUnregister notifies all registered watchers that a peer has unregistered.
func (hsv *HeliumServer) NotifyUnregister(node pkg.NodeID) (err error) {
	hsv.watchersMu.RLock()
	defer hsv.watchersMu.RUnlock()
	for _, w := range hsv.watchers {
		err = errors.Join(w.Unregister(node))
	}
	return err
}

// Register is a gRPC handler for the Register method of the Helium service.
func (hsv *HeliumServer) Register(_ *api.Void, stream api.Helium_RegisterServer) error {
	nodeId := senderIDFromIncomingContext(stream.Context())
	if len(nodeId) == 0 {
		return status.Error(codes.FailedPrecondition, "caller must specify node id for stream")
	}

	hsv.Logf("connected %s", nodeId)

	hsv.eventsMu.RLock()
	present := len(hsv.events)
	pastEvents := hsv.events

	hsv.nodesMu.Lock()
	node, has := hsv.nodes[nodeId]
	if !has {
		panic(fmt.Errorf("invalid node id: %s", nodeId))
	}
	sendQueue := make(chan coordinator.Event, 100)
	node.sendQueue = sendQueue
	hsv.nodesMu.Unlock()
	hsv.eventsMu.RUnlock() // all events after pastEvents will go on the sendQueue

	err := hsv.NotifyRegister(nodeId)
	if err != nil {
		panic(err)
	}
	hsv.Logf("registered %s", nodeId)

	err = stream.SendHeader(metadata.MD{"present": []string{strconv.Itoa(present)}})
	if err != nil {
		panic(err)
	}

	var done bool
	for _, ev := range pastEvents {
		err := stream.Send(getApiEvent(ev))
		if err != nil {
			done = true
			hsv.Logf("error while sending past events to %s: %s", nodeId, err)
			break
		}
	}
	hsv.Logf("done sending past events to %s, stream is live", nodeId)

	// Processes the node's sendQueue. The sendQueue channel is closed when exiting the loop
	cancelled := stream.Context().Done()
	for !done {
		select {
		// received an event to send or closed the queue
		case evt, more := <-sendQueue:
			if more {
				if err := stream.Send(getApiEvent(evt)); err != nil {
					done = true
					hsv.Logf("error on stream send for %s: %s", nodeId, err)
				}
			} else {
				done = true
				hsv.Logf("update queue for %s closed", nodeId)
			}

		// stream was terminated by the node or the server
		case <-cancelled:
			done = true
			close(sendQueue)
			hsv.Logf("stream context done for %s, err = %s", nodeId, stream.Context().Err())

		// the transport is closing
		case <-hsv.closing:
			close(sendQueue)
			hsv.Logf("transport closing, closing queue for %s", nodeId)
		}
	}

	hsv.nodesMu.Lock()
	node.sendQueue = nil
	hsv.nodesMu.Unlock()

	err = hsv.NotifyUnregister(nodeId)
	if err != nil {
		panic(err)
	}

	return nil
}

// PutShare is a gRPC handler for the PutShare method of the Helium service.
func (hsv *HeliumServer) PutShare(inctx context.Context, apiShare *api.Share) (*api.Void, error) {

	ctx, err := getContextFromIncomingContext(inctx) // TODO: can be moved has handler ?
	if err != nil {
		return nil, err
	}

	s, err := getShareFromAPI(apiShare)
	if err != nil {
		hsv.Logf("got an invalid share: %s", err) // TODO add details
		return nil, err
	}

	return &api.Void{}, hsv.protocolHandler.PutShare(ctx, s)
}

// GetAggregationOutput is a gRPC handler for the GetAggregationOutput method of the Helium service.
func (hsv *HeliumServer) GetAggregationOutput(inctx context.Context, apipd *api.ProtocolDescriptor) (*api.AggregationOutput, error) {

	ctx, err := getContextFromIncomingContext(inctx) // TODO: can be moved has handler ?
	if err != nil {
		return nil, err
	}

	pd := getProtocolDescFromAPI(apipd)
	out, err := hsv.protocolHandler.GetAggregationOutput(ctx, *pd)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "no output for protocol %s: %s", pd.HID(), err)
	}

	s, err := getAPIShare(&out.Share)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error converting share to API: %s", err)
	}
	apiOut := &api.AggregationOutput{AggregatedShare: s}

	peerID := senderIDFromIncomingContext(ctx)
	hsv.Logf("aggregation output %s query from %s", pd.HID(), peerID)

	return apiOut, nil
}

// GetCiphertext is a gRPC handler for the GetCiphertext method of the Helium service.
func (hsv *HeliumServer) GetCiphertext(inctx context.Context, ctid *api.CiphertextID) (*api.Ciphertext, error) {

	ctx, err := getContextFromIncomingContext(inctx) // TODO: can be moved has handler ?
	if err != nil {
		return nil, err
	}

	ct, err := hsv.ciphertextHandler.GetCiphertext(ctx, pkg.CiphertextID(ctid.CiphertextId))
	if err != nil {
		return nil, err
	}
	return ct.ToGRPC(), nil
}

// PutCiphertext is a gRPC handler for the PutCiphertext method of the Helium service.
func (hsv *HeliumServer) PutCiphertext(inctx context.Context, apict *api.Ciphertext) (*api.CiphertextID, error) {
	ct, err := pkg.NewCiphertextFromGRPC(apict)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext: %w", err)
	}

	ctx, err := getContextFromIncomingContext(inctx) // TODO: can be moved has handler ?
	if err != nil {
		return nil, err
	}

	err = hsv.ciphertextHandler.PutCiphertext(ctx, *ct)
	if err != nil {
		return nil, err
	}
	return ct.ID.ToGRPC(), nil
}

func (hsv *HeliumServer) Logf(msg string, v ...any) {
	log.Printf("%s | [HeliumServer] %s\n", hsv.id, fmt.Sprintf(msg, v...))
}
