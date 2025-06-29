package helium

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/ChristianMct/helium/api"
	"github.com/ChristianMct/helium/api/pb"
	"github.com/ChristianMct/helium/circuits"
	"github.com/ChristianMct/helium/coordinator"
	"github.com/ChristianMct/helium/node"
	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/services"
	"github.com/ChristianMct/helium/services/compute"
	"github.com/ChristianMct/helium/sessions"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

const (
	ClientConnectTimeout = 3 * time.Second
)

// HeliumClient is a client for the helium service. It is used by
// peer nodes to communicate with the helium server.
type HeliumClient struct {
	node          *node.Node
	id, helperID  sessions.NodeID
	helperAddress node.Address

	outgoingShares chan protocols.Share

	sessions.PublicKeyProvider

	*grpc.ClientConn
	pb.HeliumClient
	statsHandler
}

// Dialer is a function that returns a net.Conn to the provided address.
type Dialer = func(c context.Context, addr string) (net.Conn, error)

// NewHeliumClient creates a new helium client.
func NewHeliumClient(node *node.Node, helperID sessions.NodeID, helperAddress node.Address) *HeliumClient {
	hc := new(HeliumClient)
	hc.node = node
	hc.PublicKeyProvider = node
	hc.id = node.ID()
	hc.helperID = helperID
	hc.helperAddress = helperAddress

	return hc
}

func (hc *HeliumClient) Run(ctx context.Context, app node.App, ip compute.InputProvider) (outs <-chan circuits.Output, err error) {

	hc.outgoingShares = make(chan protocols.Share)

	go func() {
		for share := range hc.outgoingShares {
			// TODO: this is a temporary solution to distinguish between setup and compute shares.
			// A PutShare/GetShare transport interface method  with context would be cleaner
			var service string
			switch {
			case share.ProtocolType.IsSetup():
				service = "setup"
			case share.ProtocolType.IsCompute():
				service = "compute"
			default:
				panic(fmt.Errorf("unknown share type: %s", share.ProtocolType))
			}
			err := hc.PutShare(context.WithValue(ctx, services.CtxKeyName, service), share)
			if err != nil {
				panic(fmt.Errorf("error sending share: %s", err))
			}
		}
	}()

	var cdesc chan<- circuits.Descriptor
	cdesc, outs, err = hc.node.Run(ctx, app, ip, hc, hc)
	close(cdesc) // TODO: client submission of circuit descriptions is not yet supported
	return
}

func (hc *HeliumClient) OutgoingShares() chan<- protocols.Share {
	return hc.outgoingShares
}

func (hc *HeliumClient) IncomingShares() <-chan protocols.Share {
	return nil
}

// Connect establishes a connection to the helium server.
func (hc *HeliumClient) Connect() error {
	return hc.ConnectWithDialer(func(_ context.Context, _ string) (net.Conn, error) {
		return net.Dial("tcp", hc.helperAddress.String())
	})
}

func (hc *HeliumClient) Disconnect() error {
	return hc.ClientConn.Close()
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
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: time.Second, Timeout: time.Minute}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}

	ctx, cancel := context.WithTimeout(context.Background(), ClientConnectTimeout)
	defer cancel()
	var err error
	hc.ClientConn, err = grpc.DialContext(ctx, string(hc.helperAddress), opts...)
	if err != nil {
		return fmt.Errorf("fail establish connection to the helper at tcp://%s: %w", hc.helperAddress, err)
	}

	hc.HeliumClient = pb.NewHeliumClient(hc.ClientConn)

	return nil
}

// Register registers the client with the helium server and returns a channel for receiving events.
// It returns the current sequence number for the event log as present. Reading present+1 events
// from the returned channel will not block for longer than network-introduced delays.
func (hc *HeliumClient) Register(ctx context.Context) (upstream *coordinator.Channel[node.Event], present int, err error) {
	stream, err := hc.HeliumClient.Register(hc.outgoingContext(ctx), &pb.Void{})
	if err != nil {
		return nil, 0, err
	}

	present, err = readPresentFromStream(stream)
	if err != nil {
		return nil, 0, err
	}

	eventsStream := make(chan node.Event)
	go func() {
		for {
			apiEvent, err := stream.Recv()
			if err != nil {
				close(eventsStream)
				if !errors.Is(err, io.EOF) {
					log.Printf("[client] error on stream: %s", err)
				}
				return
			}

			ev := api.ToNodeEvent(apiEvent)
			eventsStream <- ev
			//log.Printf("[client] new event: %s", ev)
		}
	}()

	return &coordinator.Channel[node.Event]{Incoming: eventsStream}, present, nil
}

// PutShare sends a share to the helium server.
func (hc *HeliumClient) PutShare(ctx context.Context, share protocols.Share) error {
	apiShare, err := api.GetShare(&share)
	if err != nil {
		return err
	}
	_, err = hc.HeliumClient.PutShare(hc.outgoingContext(ctx), apiShare)
	return err
}

// GetAggregationOutput queries and returns the aggregation output for a given protocol descriptor.
func (hc *HeliumClient) GetAggregationOutput(ctx context.Context, pd protocols.Descriptor) (*protocols.AggregationOutput, error) {
	apiOut, err := hc.HeliumClient.GetAggregationOutput(hc.outgoingContext(ctx), api.GetProtocolDesc(&pd))
	if err != nil {
		return nil, err
	}

	s, err := api.ToShare(apiOut.AggregatedShare)
	if err != nil {
		return nil, err
	}
	return &protocols.AggregationOutput{Share: s, Descriptor: pd}, nil
}

// GetCiphertext queries and returns a ciphertext.
func (hc *HeliumClient) GetCiphertext(ctx context.Context, ctID sessions.CiphertextID) (*sessions.Ciphertext, error) {
	apiCt, err := hc.HeliumClient.GetCiphertext(hc.outgoingContext(ctx), &pb.CiphertextID{CiphertextId: string(ctID)})
	if err != nil {
		return nil, err
	}
	return api.ToCiphertext(apiCt)
}

// PutCiphertext sends a ciphertext to the helium server.
func (hc *HeliumClient) PutCiphertext(ctx context.Context, ct sessions.Ciphertext) error {
	apiCt, err := api.GetCiphertext(&ct)
	if err != nil {
		return err
	}
	_, err = hc.HeliumClient.PutCiphertext(hc.outgoingContext(ctx), apiCt)
	return err
}

// EvalCircuit sends a circuit to the helium server for evaluation.
// TODO: clean the cdesc submission API (and the output one ?)
func (hc *HeliumClient) EvalCircuit(ctx context.Context, cd circuits.Descriptor) error {
	_, err := hc.HeliumClient.EvalCircuit(hc.outgoingContext(ctx), api.GetCircuitDesc(cd))
	return err
}

func (hc *HeliumClient) outgoingContext(ctx context.Context) context.Context {
	ctx = sessions.ContextWithNodeID(ctx, hc.id) // TODO would be better to ensure that a node always has its id in a context
	ctx, err := getOutgoingContext(ctx)
	if err != nil {
		panic(err)
	}
	return ctx
}

func (hc *HeliumClient) NodeID() sessions.NodeID {
	return hc.node.ID()
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
