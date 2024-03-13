package centralized

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/coordinator"
	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/protocols"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	ClientConnectTimeout = 3 * time.Second
)

// HeliumClient is a client for the helium service. It is used by
// peer nodes to communicate with the helium server.
type HeliumClient struct {
	ownId, helperId pkg.NodeID
	helperAddress   pkg.NodeAddress

	api.HeliumClient
	statsHandler
}

// NewHeliumClient creates a new helium client.
func NewHeliumClient(ownId, helperId pkg.NodeID, helperAddress pkg.NodeAddress) *HeliumClient {
	hc := new(HeliumClient)
	hc.ownId = ownId
	hc.helperId = helperId
	hc.helperAddress = helperAddress
	return hc
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
		//grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: time.Second, Timeout: time.Minute}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}

	ctx, cancel := context.WithTimeout(context.Background(), ClientConnectTimeout)
	defer cancel()
	cc, err := grpc.DialContext(ctx, string(hc.helperAddress), opts...)
	if err != nil {
		return fmt.Errorf("fail establish connection to the helper at tcp://%s: %w", hc.helperAddress, err)
	}

	hc.HeliumClient = api.NewHeliumClient(cc)

	return nil
}

// Register registers the client with the helium server and returns a channel for receiving events.
// It returns the current sequence number for the event log as present. Reading present+1 events
// from the returned channel will not block for longer than network-introduced delays.
func (hc *HeliumClient) Register(ctx context.Context) (events <-chan coordinator.Event, present int, err error) {
	stream, err := hc.HeliumClient.Register(hc.outgoingContext(ctx), &api.Void{})
	if err != nil {
		return nil, 0, err
	}

	present, err = readPresentFromStream(stream)
	if err != nil {
		return nil, 0, err
	}

	eventsStream := make(chan coordinator.Event)
	go func() {
		for {
			apiEvent, err := stream.Recv()
			if err != nil {
				close(eventsStream)
				if !errors.Is(err, io.EOF) {
					panic(fmt.Errorf("error on stream: %s", err))
				}
				return
			}
			eventsStream <- getEventFromAPI(apiEvent)
		}
	}()
	events = eventsStream
	return
}

// PutShare sends a share to the helium server.
func (hc *HeliumClient) PutShare(ctx context.Context, share protocols.Share) error {
	apiShare, err := getAPIShare(&share)
	if err != nil {
		return err
	}
	_, err = hc.HeliumClient.PutShare(hc.outgoingContext(ctx), apiShare)
	return err
}

// GetAggregationOutput queries and returns the aggregation output for a given protocol descriptor.
func (hc *HeliumClient) GetAggregationOutput(ctx context.Context, pd protocols.Descriptor) (*protocols.AggregationOutput, error) {
	apiOut, err := hc.HeliumClient.GetAggregationOutput(hc.outgoingContext(ctx), getAPIProtocolDesc(&pd))
	if err != nil {
		return nil, err
	}

	s, err := getShareFromAPI(apiOut.AggregatedShare)
	if err != nil {
		return nil, err
	}
	return &protocols.AggregationOutput{Share: s, Descriptor: pd}, nil
}

// GetCiphertext queries and returns a ciphertext.
func (hc *HeliumClient) GetCiphertext(ctx context.Context, ctID pkg.CiphertextID) (*pkg.Ciphertext, error) {
	apiCt, err := hc.HeliumClient.GetCiphertext(hc.outgoingContext(ctx), ctID.ToGRPC())
	if err != nil {
		return nil, err
	}
	return pkg.NewCiphertextFromGRPC(apiCt)
}

// PutCiphertext sends a ciphertext to the helium server.
func (hc *HeliumClient) PutCiphertext(ctx context.Context, ct pkg.Ciphertext) error {
	_, err := hc.HeliumClient.PutCiphertext(hc.outgoingContext(ctx), ct.ToGRPC())
	return err
}

func (hc *HeliumClient) outgoingContext(ctx context.Context) context.Context {
	return pkg.GetOutgoingContext(ctx, hc.ownId)
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
