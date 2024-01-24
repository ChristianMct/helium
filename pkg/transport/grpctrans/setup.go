package grpctrans

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strconv"
	"sync"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/protocols"
	"github.com/ldsec/helium/pkg/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const peerProtocolUpdateQueueSize = 10000 // TODO: find way to size that better

type setupTransport struct {
	*Transport
	*ShareTransport

	*api.UnimplementedSetupServiceServer

	srvHandler transport.SetupServiceHandler

	protocolUpdates   []protocols.StatusUpdate
	protocolUpdatesMu sync.RWMutex

	transportDone chan struct{}
	mPeers        sync.RWMutex
	peers         map[pkg.NodeID]*SetupPeer
}

func (t *Transport) newSetupTransport() *setupTransport {
	pc := new(setupTransport)
	pc.Transport = t
	pc.ShareTransport = t.NewShareTransport()

	pc.protocolUpdates = make([]protocols.StatusUpdate, 0)

	pc.transportDone = make(chan struct{})
	pc.peers = make(map[pkg.NodeID]*SetupPeer)
	for _, nid := range pc.nodeList {
		pc.peers[nid.NodeID] = &SetupPeer{
			id: nid.NodeID,
		}
	}
	return pc
}

func (t *setupTransport) registerService(srv transport.SetupServiceHandler) {
	t.srvHandler = srv
}

func (t *setupTransport) connect() {
	t.ShareTransport.Run()
	peerClis := make(map[pkg.NodeID]ShareTransportClient)
	for peerID, peerCli := range t.conns {
		t.peers[peerID].cli = api.NewSetupServiceClient(peerCli)
		peerClis[peerID] = &setupServiceClientWrapper{t.peers[peerID].cli}
	}
	err := t.ShareTransport.Connect(peerClis)
	if err != nil {
		panic(err)
	}
}

func (t *setupTransport) PutProtocolUpdate(pu protocols.StatusUpdate) (seq int, err error) {
	t.protocolUpdatesMu.Lock()
	seq = len(t.protocolUpdates)
	t.protocolUpdates = append(t.protocolUpdates, pu)

	t.mPeers.RLock()
	for _, peer := range t.peers {
		if peer.connected {
			peer.protocolUpdateQueue <- pu
		}
	}
	t.mPeers.RUnlock()
	t.protocolUpdatesMu.Unlock()
	return seq, nil
}

func (t *setupTransport) RegisterForSetupAt(ctx context.Context, peerID pkg.NodeID) (<-chan protocols.StatusUpdate, int, error) {

	peer, exists := t.peers[peerID]
	if !exists {
		return nil, 0, fmt.Errorf("peer does not exists: %s", peerID)
	}

	if peer.cli == nil {
		return nil, 0, fmt.Errorf("peer is not connected: %s", peerID)
	}

	stream, err := peer.cli.RegisterForSetup(ctx, &api.Void{})
	if err != nil {
		return nil, 0, err
	}

	present, err := readPresentFromStream(stream)
	if err != nil {
		return nil, 0, err
	}

	descStream := make(chan protocols.StatusUpdate)
	go func() {

		for {
			pu, errRcv := stream.Recv()
			if errRcv != nil {
				close(descStream)
				if !errors.Is(errRcv, io.EOF) {
					panic(errRcv)
				}
				return
			}
			desc := getProtocolDescFromAPI(pu.ProtocolDescriptor)
			descStream <- protocols.StatusUpdate{Descriptor: *desc, Status: protocols.Status(pu.ProtocolStatus)}
		}

	}()

	return descStream, present, nil
}

func getAPIProtocolDesc(pd *protocols.Descriptor) *api.ProtocolDescriptor {
	apiDesc := &api.ProtocolDescriptor{
		ProtocolType: api.ProtocolType(pd.Signature.Type),
		Args:         make(map[string]string, len(pd.Signature.Args)),
		Aggregator:   &api.NodeID{NodeId: string(pd.Aggregator)},
		Participants: make([]*api.NodeID, 0, len(pd.Participants)),
	}
	for k, v := range pd.Signature.Args {
		apiDesc.Args[k] = v
	}
	for _, p := range pd.Participants {
		apiDesc.Participants = append(apiDesc.Participants, &api.NodeID{NodeId: string(p)})
	}
	return apiDesc
}

func getProtocolDescFromAPI(apiPD *api.ProtocolDescriptor) *protocols.Descriptor {
	desc := &protocols.Descriptor{
		Signature:    protocols.Signature{Type: protocols.Type(apiPD.ProtocolType), Args: make(map[string]string)},
		Aggregator:   pkg.NodeID(apiPD.Aggregator.NodeId),
		Participants: make([]pkg.NodeID, 0, len(apiPD.Participants)),
	}
	for k, v := range apiPD.Args {
		desc.Signature.Args[k] = v
	}
	for _, p := range apiPD.Participants {
		desc.Participants = append(desc.Participants, pkg.NodeID(p.NodeId))
	}
	return desc
}

func (t *setupTransport) GetAggregationFrom(ctx context.Context, nid pkg.NodeID, pd protocols.Descriptor) (*protocols.AggregationOutput, error) {
	peer, exists := t.peers[nid]
	if !exists {
		return nil, fmt.Errorf("peer with id `%s` does not exist", nid)
	}

	apiOut, err := peer.cli.GetAggregationOutput(ctx, getAPIProtocolDesc(&pd))
	if err != nil {
		return nil, err
	}

	s, err := getShareFromAPI(apiOut.AggregatedShare)
	if err != nil {
		return nil, err
	}
	return &protocols.AggregationOutput{Share: s}, nil
}

func (t *setupTransport) RegisterForSetup(_ *api.Void, stream api.SetupService_RegisterForSetupServer) error {
	peerID := pkg.SenderIDFromIncomingContext(stream.Context())
	if peerID == "" {
		return fmt.Errorf("client must specify node id for stream")
	}

	peerUpdateQueue := make(chan protocols.StatusUpdate, peerProtocolUpdateQueueSize)

	t.protocolUpdatesMu.Lock()
	present := len(t.protocolUpdates)

	t.mPeers.Lock()
	peer, has := t.peers[peerID]
	if !has {
		t.mPeers.Unlock()
		return fmt.Errorf("unexpected peer id: %s", peerID)
	}
	if peer.connected {
		panic("peer already registered")
	}
	peer.connected = true
	peer.protocolUpdateQueue = peerUpdateQueue

	stream.SetHeader(metadata.MD{"present": []string{strconv.Itoa(present)}})
	for _, pu := range t.protocolUpdates {
		peerUpdateQueue <- pu
	}

	t.mPeers.Unlock()
	t.protocolUpdatesMu.Unlock()

	err := t.srvHandler.Register(peerID)
	if err != nil {
		return err
	}

	var done bool
	for !done {
		select {
		case pu, more := <-peerUpdateQueue:
			if more {
				apiDesc := getAPIProtocolDesc(&pu.Descriptor)
				err := stream.Send(&api.ProtocolUpdate{ProtocolDescriptor: apiDesc, ProtocolStatus: api.ProtocolStatus(pu.Status)})
				if err != nil {
					done = true
				}
			} else {
				done = true
			}
		case <-t.transportDone:
			//done = true
			// empties the queue
			for !done {
				select {
				case pu := <-peerUpdateQueue:
					apiDesc := getAPIProtocolDesc(&pu.Descriptor)
					err := stream.Send(&api.ProtocolUpdate{ProtocolDescriptor: apiDesc, ProtocolStatus: api.ProtocolStatus(pu.Status)})
					if err != nil {
						done = true
					}
				default:
					done = true
				}
			}
		case <-stream.Context().Done():
			done = true

		}
	}

	t.mPeers.Lock()
	close(peerUpdateQueue)
	peer.connected = false
	t.mPeers.Unlock()
	return t.srvHandler.Unregister(peerID)
}

func (t *setupTransport) GetAggregationOutput(ctx context.Context, apipd *api.ProtocolDescriptor) (*api.AggregationOutput, error) {
	pd := getProtocolDescFromAPI(apipd)
	out, err := t.srvHandler.GetProtocolOutput(*pd)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "no output for protocol %s", pd.HID())
	}

	s, err := getAPIShare(&out.Share)
	if err != nil {
		return nil, err
	}
	apiOut := &api.AggregationOutput{AggregatedShare: s}

	peerID := pkg.SenderIDFromIncomingContext(ctx)
	log.Printf("%s | aggregation output %s query from %s", t.id, pd.HID(), peerID)

	return apiOut, nil
}

func (t *setupTransport) PutShare(ctx context.Context, share *api.Share) (*api.Void, error) {
	return t.ShareTransport.PutShare(ctx, share)
}

func (t *setupTransport) StreamShares(stream api.SetupService_StreamSharesServer) error {
	return t.ShareTransport.StreamShares(stream)
}

func (t *setupTransport) Close() {
	close(t.transportDone)
}

type setupServiceClientWrapper struct {
	api.SetupServiceClient
}

func (scw *setupServiceClientWrapper) StreamShares(ctx context.Context, opts ...grpc.CallOption) (ShareStreamClient, error) {
	return scw.SetupServiceClient.StreamShares(ctx, opts...)
}
