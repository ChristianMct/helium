package centralized

import (
	"context"
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
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	MaxMsgSize       = 1024 * 1024 * 32
	KeepaliveTime    = time.Second
	KeepaliveTimeout = time.Second
)

type ProtocolHandler interface {
	// GetProtocolOutput returns the aggregation output for the designated protocol
	// or an error if such output does not exist.
	PutShare(protocols.Share) error
	GetProtocolOutput(protocols.Descriptor) (*protocols.AggregationOutput, error)
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
	events   coordinator.Log
	eventsMu sync.RWMutex
	nodes    map[pkg.NodeID]*client
	nodesMu  sync.RWMutex
	closing  chan struct{}

	// service API
	protocolHandler   ProtocolHandler
	ciphertextHandler CiphertextHandler

	// grpc API
	*grpc.Server
	api.UnimplementedHeliumHelperServer
	statsHandler statsHandler
}

func NewHeliumServer(id pkg.NodeID, na pkg.NodeAddress, nl pkg.NodesList) *HeliumServer {
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
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    KeepaliveTime,
			Timeout: KeepaliveTime,
		}),
	}

	hsv.Server = grpc.NewServer(serverOpts...)
	hsv.Server.RegisterService(&api.HeliumHelper_ServiceDesc, hsv)

	return hsv
}

func (ct *HeliumServer) Register(_ *api.Void, stream api.Coordinator_RegisterServer) error {
	nodeId := pkg.SenderIDFromIncomingContext(stream.Context())
	if len(nodeId) == 0 {
		return fmt.Errorf("caller must specify node id for stream")
	}

	ct.Logf("connected %s", nodeId)

	ct.eventsMu.RLock()
	present := len(ct.events)
	pastEvents := ct.events
	ct.nodesMu.Lock()
	node, has := ct.nodes[nodeId]
	if has {
		panic(fmt.Errorf("peer already registered: %s", nodeId))
	}
	sendQueue := make(chan coordinator.Event, 100)
	node.sendQueue = sendQueue
	ct.nodesMu.Unlock()
	ct.eventsMu.RUnlock() // all events after pastEvents will go on the sendQueue

	ct.Logf("registered %s", nodeId)

	var done bool
	stream.SetHeader(metadata.MD{"present": []string{strconv.Itoa(present)}})
	for _, ev := range pastEvents {
		err := stream.Send(getApiEvent(ev))
		if err != nil {
			done = true
			ct.Logf("error while sending past events to %s: %s", nodeId, err)
			break
		}
	}

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

	return nil
}

// PutShare is used to push the caller's share in the protocol described by the Share.ShareDescriptor
// field to the callee.
func (hsv *HeliumServer) PutShare(ctx context.Context, apiShare *api.Share) (*api.Void, error) {
	s, err := getShareFromAPI(apiShare)
	if err != nil {
		hsv.Logf("got an invalid share") // TODO add details
		return nil, err
	}

	return &api.Void{}, hsv.protocolHandler.PutShare(s)
}

func (hsv *HeliumServer) GetAggregationOutput(ctx context.Context, apipd *api.ProtocolDescriptor) (*api.AggregationOutput, error) {
	pd := getProtocolDescFromAPI(apipd)
	out, err := hsv.protocolHandler.GetProtocolOutput(*pd)
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

func (hsv *HeliumServer) GetCiphertext(ctx context.Context, ctr *api.CiphertextRequest) (*api.Ciphertext, error) {
	ct, err := hsv.ciphertextHandler.GetCiphertext(ctx, pkg.CiphertextID(ctr.Id.CiphertextId))
	if err != nil {
		return nil, err
	}
	return ct.ToGRPC(), nil
}

func (hsv *HeliumServer) PutCiphertext(ctx context.Context, apict *api.Ciphertext) (*api.CiphertextID, error) {
	ct, err := pkg.NewCiphertextFromGRPC(apict)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext: %w", err)
	}
	err = hsv.ciphertextHandler.PutCiphertext(ctx, *ct)
	if err != nil {
		return nil, err
	}
	return ct.ID.ToGRPC(), nil
}

func (ct *HeliumServer) Logf(msg string, v ...any) {
	log.Printf("%s | [HeliumServer] %s\n", ct.id, fmt.Sprintf(msg, v...))
}
