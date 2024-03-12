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
	"github.com/ldsec/helium/pkg/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	ClientConnectTimeout = 3 * time.Second
)

type HeliumClient struct {
	ownId, helperId pkg.NodeID
	helperAddress   pkg.NodeAddress

	api.HeliumHelperClient
	statsHandler statsHandler
}

func NewHeliumClient(ownId, helperId pkg.NodeID, helperAddress pkg.NodeAddress) *HeliumClient {
	hc := new(HeliumClient)
	hc.ownId = ownId
	hc.helperId = helperId
	hc.helperAddress = helperAddress
	return hc
}

func (hc *HeliumClient) Connect() error {
	return hc.ConnectWithDialer(func(_ context.Context, _ string) (net.Conn, error) {
		return net.Dial("tcp", hc.helperAddress.String())
	})
}

func (hc *HeliumClient) ConnectWithDialer(dialer transport.Dialer) error {
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

	hc.HeliumHelperClient = api.NewHeliumHelperClient(cc)

	return nil
}

func (hc *HeliumClient) Register(ctx context.Context) (events <-chan coordinator.Event, present int, err error) {
	stream, err := hc.HeliumHelperClient.Register(hc.outgoingContext(ctx), &api.Void{})
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

func (hc *HeliumClient) PutShare(ctx context.Context, share protocols.Share) error {
	apiShare, err := getAPIShare(&share)
	if err != nil {
		return err
	}
	_, err = hc.HeliumHelperClient.PutShare(hc.outgoingContext(ctx), apiShare)
	return err
}

func (hc *HeliumClient) GetAggregationOutput(ctx context.Context, pd protocols.Descriptor) (*protocols.AggregationOutput, error) {
	apiOut, err := hc.HeliumHelperClient.GetAggregationOutput(hc.outgoingContext(ctx), getAPIProtocolDesc(&pd))
	if err != nil {
		return nil, err
	}

	s, err := getShareFromAPI(apiOut.AggregatedShare)
	if err != nil {
		return nil, err
	}
	return &protocols.AggregationOutput{Share: s, Descriptor: pd}, nil
}

func (hc *HeliumClient) GetCiphertext(ctx context.Context, ctID pkg.CiphertextID) (*pkg.Ciphertext, error) {
	apiCt, err := hc.HeliumHelperClient.GetCiphertext(hc.outgoingContext(ctx), &api.CiphertextRequest{Id: ctID.ToGRPC()})
	if err != nil {
		return nil, err
	}
	return pkg.NewCiphertextFromGRPC(apiCt)
}

func (hc *HeliumClient) PutCiphertext(ctx context.Context, ct pkg.Ciphertext) error {
	_, err := hc.HeliumHelperClient.PutCiphertext(hc.outgoingContext(ctx), ct.ToGRPC())
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
