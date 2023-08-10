package grpctrans

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/protocols"
	"github.com/ldsec/helium/pkg/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type setupTransport struct {
	*Transport
	*ShareTransport

	*api.UnimplementedSetupServiceServer

	srvHandler transport.SetupServiceHandler

	outgoingProtocolUpdates     chan protocols.StatusUpdate
	outgoingProtocolUpdatesDone chan struct{}

	mPeers sync.RWMutex
	peers  map[pkg.NodeID]*Peer
}

func (t *Transport) newSetupTransport() *setupTransport {
	pc := new(setupTransport)
	pc.Transport = t
	pc.ShareTransport = t.NewShareTransport()

	pc.outgoingProtocolUpdates = make(chan protocols.StatusUpdate)
	pc.outgoingProtocolUpdatesDone = make(chan struct{})

	pc.peers = make(map[pkg.NodeID]*Peer)
	for _, nid := range pc.nodeList {
		pc.peers[nid.NodeID] = &Peer{
			id: nid.NodeID,
		}
	}

	go func() {

		for pd := range pc.outgoingProtocolUpdates {

			subscribed := make([]*Peer, 0, len(pc.peers))
			pc.mPeers.RLock()
			for _, peer := range pc.peers {
				if peer.connected {
					subscribed = append(subscribed, peer)
				}
			}
			pc.mPeers.RUnlock()

			for _, sub := range subscribed {
				sub.SendUpdate(pd)
			}
		}

		subscribed := make([]*Peer, 0, len(pc.peers))
		pc.mPeers.RLock()
		for _, peer := range pc.peers {
			if peer.connected {
				subscribed = append(subscribed, peer)
			}
		}
		pc.mPeers.RUnlock()

		close(pc.outgoingProtocolUpdatesDone)
		for _, sub := range subscribed {
			sub.protoUpdateStreamDone <- true
		}
	}()

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

func (t *setupTransport) RegisterForSetupAt(ctx context.Context, peerID pkg.NodeID) (<-chan protocols.StatusUpdate, error) {

	peer, exists := t.peers[peerID]
	if !exists {
		return nil, fmt.Errorf("peer does not exists: %s", peerID)
	}

	if peer.cli == nil {
		return nil, fmt.Errorf("peer is not connected: %s", peerID)
	}

	stream, err := peer.cli.RegisterForSetup(ctx, &api.Void{})
	if err != nil {
		panic(err)
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

	return descStream, nil
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

func (t *setupTransport) OutgoingProtocolUpdates() chan<- protocols.StatusUpdate {
	return t.outgoingProtocolUpdates
}

func (t *setupTransport) RegisterForSetup(_ *api.Void, stream api.SetupService_RegisterForSetupServer) error {
	peerID := pkg.SenderIDFromIncomingContext(stream.Context())
	if peerID == "" {
		return fmt.Errorf("client must specify node id for stream")
	}
	t.mPeers.Lock()
	peer := t.peers[peerID]
	peer.connected = true
	peer.protoUpdateStream = stream
	peer.protoUpdateStreamDone = make(chan bool)
	t.mPeers.Unlock()

	err := t.srvHandler.Register(transport.Peer{PeerID: peerID})
	if err != nil {
		return err
	}

	for _, psu := range t.srvHandler.GetProtocolStatus() {
		peer.SendUpdate(psu)
	}

	select {
	case <-t.outgoingProtocolUpdatesDone:
	case <-peer.protoUpdateStreamDone:
	case <-stream.Context().Done():
	}

	t.mPeers.Lock()
	peer.connected = false
	peer.protoUpdateStream = nil
	t.mPeers.Unlock()
	return t.srvHandler.Unregister(transport.Peer{PeerID: peerID})
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

type setupServiceClientWrapper struct {
	api.SetupServiceClient
}

func (scw *setupServiceClientWrapper) StreamShares(ctx context.Context, opts ...grpc.CallOption) (ShareStreamClient, error) {
	return scw.SetupServiceClient.StreamShares(ctx, opts...)
}
