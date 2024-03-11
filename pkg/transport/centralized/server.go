package centralized

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/coordinator"
	"github.com/ldsec/helium/pkg/pkg"
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

type NodeWatcher interface {
	// Register is called by the transport when a new peer register itself for the setup.
	Register(pkg.NodeID) error

	// Unregister is called by the transport when a peer is unregistered from the setup.
	Unregister(pkg.NodeID) error
}

type ProtocolHandler interface {
	PutShare(context.Context, protocols.Share) error
	GetAggregationOutput(context.Context, protocols.Descriptor) (*protocols.AggregationOutput, error)
}

type CiphertextHandler interface {
	GetCiphertext(context.Context, pkg.CiphertextID) (*pkg.Ciphertext, error)
	PutCiphertext(context.Context, pkg.Ciphertext) error
}

type client struct {
	sendQueue chan coordinator.Event
}

type HeliumServer struct {
	id pkg.NodeID

	// synchronization
	events       coordinator.Log
	eventsClosed bool
	eventsMu     sync.RWMutex
	nodes        map[pkg.NodeID]*client
	nodesMu      sync.RWMutex
	closing      chan struct{}

	// service API
	protocolHandler   ProtocolHandler
	ciphertextHandler CiphertextHandler
	watchers          []NodeWatcher

	// grpc API
	*grpc.Server
	*api.UnimplementedHeliumHelperServer
	statsHandler statsHandler
}

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
	hsv.Server.RegisterService(&api.HeliumHelper_ServiceDesc, hsv)

	hsv.protocolHandler = protoHandler
	hsv.ciphertextHandler = ctxtHandler
	hsv.watchers = make([]NodeWatcher, 0)

	hsv.nodes = make(map[pkg.NodeID]*client)
	for _, n := range nl {
		hsv.nodes[n.NodeID] = &client{}
	}

	return hsv
}

func (ct *HeliumServer) SendEvent(event coordinator.Event) error {
	ct.eventsMu.Lock()
	ct.events = append(ct.events, event)

	ct.nodesMu.RLock()
	for nodeId, node := range ct.nodes {
		if node.sendQueue != nil {
			select {
			case node.sendQueue <- event:
			default:
				panic(fmt.Errorf("node %s has full send queue", nodeId)) // TODO: handle this by closing stream instead
			}
		}
	}
	ct.nodesMu.RUnlock()
	ct.eventsMu.Unlock()
	return nil
}

func (ct *HeliumServer) CloseEvents() {
	ct.eventsMu.Lock()
	if ct.eventsClosed {
		panic("events already closed")
	}
	ct.nodesMu.Lock()
	ct.eventsClosed = true
	for _, c := range ct.nodes {
		if c.sendQueue != nil {
			close(c.sendQueue)
		}
	}
	ct.nodesMu.Unlock()
	ct.eventsMu.Unlock()
}

func (ct *HeliumServer) Register(_ *api.Void, stream api.HeliumHelper_RegisterServer) error {
	nodeId := pkg.SenderIDFromIncomingContext(stream.Context())
	if len(nodeId) == 0 {
		return status.Error(codes.FailedPrecondition, "caller must specify node id for stream")
	}

	ct.Logf("connected %s", nodeId)

	ct.eventsMu.RLock()
	present := len(ct.events)
	pastEvents := ct.events

	ct.nodesMu.Lock()
	node, has := ct.nodes[nodeId]
	if !has {
		panic(fmt.Errorf("invalid node id: %s", nodeId))
	}
	sendQueue := make(chan coordinator.Event, 100)
	node.sendQueue = sendQueue
	ct.nodesMu.Unlock()
	ct.eventsMu.RUnlock() // all events after pastEvents will go on the sendQueue

	err := ct.NotifyRegister(nodeId)
	if err != nil {
		panic(err)
	}
	ct.Logf("registered %s", nodeId)

	err = stream.SendHeader(metadata.MD{"present": []string{strconv.Itoa(present)}})
	if err != nil {
		panic(err)
	}

	var done bool
	for _, ev := range pastEvents {
		err := stream.Send(getApiEvent(ev))
		if err != nil {
			done = true
			ct.Logf("error while sending past events to %s: %s", nodeId, err)
			break
		}
	}
	ct.Logf("done sending past events to %s, stream is live", nodeId)

	// Processes the node's sendQueue. The sendQueue channel is closed when exiting the loop
	cancelled := stream.Context().Done()
	for !done {
		select {
		// received an event to send or closed the queue
		case evt, more := <-sendQueue:
			if more {
				if err := stream.Send(getApiEvent(evt)); err != nil {
					done = true
					ct.Logf("error on stream send for %s: %s", nodeId, err)
				}
			} else {
				done = true
				ct.Logf("update queue for %s closed", nodeId)
			}

		// stream was terminated by the node or the server
		case <-cancelled:
			done = true
			close(sendQueue)
			ct.Logf("stream context done for %s, err = %s", nodeId, stream.Context().Err())

		// the transport is closing
		case <-ct.closing:
			close(sendQueue)
			ct.Logf("transport closing, closing queue for %s", nodeId)
		}
	}

	ct.nodesMu.Lock()
	node.sendQueue = nil
	ct.nodesMu.Unlock()

	err = ct.NotifyUnregister(nodeId)
	if err != nil {
		panic(err)
	}

	return nil
}

// PutShare is used to push the caller's share in the protocol described by the Share.ShareDescriptor
// field to the callee.
func (hsv *HeliumServer) PutShare(inctx context.Context, apiShare *api.Share) (*api.Void, error) {

	ctx, err := pkg.GetContextFromIncomingContext(inctx) // TODO: can be moved has handler ?
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

func (hsv *HeliumServer) GetAggregationOutput(inctx context.Context, apipd *api.ProtocolDescriptor) (*api.AggregationOutput, error) {

	ctx, err := pkg.GetContextFromIncomingContext(inctx) // TODO: can be moved has handler ?
	if err != nil {
		return nil, err
	}

	pd := getProtocolDescFromAPI(apipd)
	out, err := hsv.protocolHandler.GetAggregationOutput(ctx, *pd)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "no output for protocol %s", pd.HID())
	}

	s, err := getAPIShare(&out.Share)
	if err != nil {
		return nil, err
	}
	apiOut := &api.AggregationOutput{AggregatedShare: s}

	peerID := pkg.SenderIDFromIncomingContext(ctx)
	hsv.Logf("aggregation output %s query from %s", pd.HID(), peerID)

	return apiOut, nil
}

func (hsv *HeliumServer) GetCiphertext(inctx context.Context, ctr *api.CiphertextRequest) (*api.Ciphertext, error) {

	ctx, err := pkg.GetContextFromIncomingContext(inctx) // TODO: can be moved has handler ?
	if err != nil {
		return nil, err
	}

	ct, err := hsv.ciphertextHandler.GetCiphertext(ctx, pkg.CiphertextID(ctr.Id.CiphertextId))
	if err != nil {
		return nil, err
	}
	return ct.ToGRPC(), nil
}

func (hsv *HeliumServer) PutCiphertext(inctx context.Context, apict *api.Ciphertext) (*api.CiphertextID, error) {
	ct, err := pkg.NewCiphertextFromGRPC(apict)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext: %w", err)
	}

	ctx, err := pkg.GetContextFromIncomingContext(inctx) // TODO: can be moved has handler ?
	if err != nil {
		return nil, err
	}

	err = hsv.ciphertextHandler.PutCiphertext(ctx, *ct)
	if err != nil {
		return nil, err
	}
	return ct.ID.ToGRPC(), nil
}

func (hsv *HeliumServer) RegisterWatcher(nw NodeWatcher) {
	hsv.watchers = append(hsv.watchers, nw)
}

func (hsv *HeliumServer) NotifyRegister(node pkg.NodeID) (err error) {
	for _, w := range hsv.watchers {
		err = errors.Join(w.Register(node))
	}
	return
}

func (hsv *HeliumServer) NotifyUnregister(node pkg.NodeID) (err error) {
	for _, w := range hsv.watchers {
		err = errors.Join(w.Unregister(node))
	}
	return
}

func (ct *HeliumServer) Logf(msg string, v ...any) {
	log.Printf("%s | [HeliumServer] %s\n", ct.id, fmt.Sprintf(msg, v...))
}
