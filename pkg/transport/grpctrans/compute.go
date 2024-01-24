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
	"github.com/ldsec/helium/pkg/circuits"
	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/protocols"
	"github.com/ldsec/helium/pkg/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const peerCircuitUpdateQueueSize = 100000 // TODO: find way to size that better

type computeTransport struct {
	*Transport
	*ShareTransport

	api.UnimplementedComputeServiceServer

	srvHandler transport.ComputeServiceHandler

	circuitUpdates  []circuits.Update
	mCircuitUpdates sync.RWMutex

	transportDone chan struct{}
	mPeers        sync.RWMutex
	peers         map[pkg.NodeID]*ComputePeer
}

func (t *Transport) newComputeTransport() *computeTransport {
	pc := new(computeTransport)
	pc.Transport = t
	pc.ShareTransport = t.NewShareTransport()

	pc.circuitUpdates = make([]circuits.Update, 0)

	pc.transportDone = make(chan struct{})
	pc.peers = make(map[pkg.NodeID]*ComputePeer)
	for _, nid := range pc.nodeList {
		pc.peers[nid.NodeID] = &ComputePeer{
			id: nid.NodeID,
		}
	}

	return pc
}

func (env *computeTransport) registerService(srv transport.ComputeServiceHandler) {
	env.srvHandler = srv
}

func (env *computeTransport) connect() {
	env.ShareTransport.Run()

	peerClis := make(map[pkg.NodeID]ShareTransportClient)
	for peerID, peerConn := range env.conns {
		env.peers[peerID].cli = api.NewComputeServiceClient(peerConn)
		peerClis[peerID] = &computeServiceClientWrapper{env.peers[peerID].cli}
	}
	err := env.ShareTransport.Connect(peerClis)
	if err != nil {
		panic(err)
	}
}

func (env *computeTransport) PutCircuitUpdates(cu circuits.Update) (seq int, err error) {
	env.mCircuitUpdates.Lock()
	seq = len(env.circuitUpdates)
	env.circuitUpdates = append(env.circuitUpdates, cu)

	env.mPeers.RLock()
	for _, peer := range env.peers {
		if peer.connected {
			peer.circuitUpdateQueue <- cu
			//log.Printf("queued cu to %s: %+v", peer.id, cu)
		}
	}
	env.mPeers.RUnlock()
	env.mCircuitUpdates.Unlock()

	return seq, nil
}

func (env *computeTransport) Close() {
	close(env.transportDone)
}

func (env *computeTransport) GetCiphertext(ctx context.Context, ctID pkg.CiphertextID) (*pkg.Ciphertext, error) {
	ctURL, err := pkg.ParseURL(string(ctID))
	if err != nil {
		return nil, err
	}

	host := ctURL.NodeID()
	if host == "" {
		return nil, fmt.Errorf("ciphertext id is local id")
	}

	peer, exists := env.peers[host]
	if !exists {
		return nil, fmt.Errorf("peer with id %s does not exist", host)
	}

	// DEBUG
	//log.Printf("[GetCipherText] fetching ctID %v, host: %v, peer: %v", ctID, host, peer)

	if peer == nil {
		return nil, fmt.Errorf("peer with id %s is a light node", host)
	}

	outCtx := pkg.GetOutgoingContext(ctx, env.id)
	apiCt, err := peer.cli.GetCiphertext(outCtx, &api.CiphertextRequest{Id: ctID.ToGRPC()})
	if err != nil {
		return nil, err
	}
	return pkg.NewCiphertextFromGRPC(apiCt)
}

func (env *computeTransport) PutCiphertext(ctx context.Context, nodeID pkg.NodeID, ct pkg.Ciphertext) error {
	if nodeID == env.id {
		return env.srvHandler.PutCiphertext(ctx, ct)
	}
	peer, exists := env.peers[nodeID]
	if !exists {
		panic(fmt.Errorf("not connected to party %s", nodeID))
	}
	ctx = pkg.GetOutgoingContext(ctx, env.id)
	_, err := peer.cli.PutCiphertext(ctx, ct.ToGRPC())
	if err != nil {
		log.Printf("error while sending ciphertext: %s", err)
	}
	return nil
}

func SendUpdate(cu circuits.Update, stream api.ComputeService_RegisterForComputeServer) error {

	apiCU := &api.ComputeUpdate{ComputeSignature: &api.ComputeSignature{CircuitName: cu.CircuitName, CircuitID: string(cu.CircuitID)}, ComputeStatus: api.ComputeStatus(cu.Status)}
	if cu.StatusUpdate != nil {
		apiDesc := getAPIProtocolDesc(&cu.StatusUpdate.Descriptor)
		apiCU.ProtocolUpdate = &api.ProtocolUpdate{ProtocolDescriptor: apiDesc, ProtocolStatus: api.ProtocolStatus(cu.StatusUpdate.Status)}
	}
	return stream.Send(apiCU)
}

func (t *computeTransport) RegisterForCompute(_ *api.Void, stream api.ComputeService_RegisterForComputeServer) error {
	peerID := pkg.SenderIDFromIncomingContext(stream.Context())
	if peerID == "" {
		return fmt.Errorf("client must specify node id for stream")
	}

	peerCircuitUpdateQueue := make(chan circuits.Update, peerCircuitUpdateQueueSize)

	t.mCircuitUpdates.RLock() // locks the updates while populating the past message queue

	t.mPeers.Lock() // updates the peer status to online, peer will recieve subsequent updates on its queue
	peer, has := t.peers[peerID]
	if !has {
		t.mPeers.Unlock()
		return fmt.Errorf("unexpected peer id: %s", peerID)
	}
	if peer.connected {
		panic("peer already registered")
	}
	peer.connected = true
	peer.circuitUpdateQueue = peerCircuitUpdateQueue

	present := len(t.circuitUpdates)
	stream.SetHeader(metadata.MD{"present": []string{strconv.Itoa(present)}})
	for _, cu := range t.circuitUpdates {
		peerCircuitUpdateQueue <- cu
	}

	t.mPeers.Unlock()
	t.mCircuitUpdates.RUnlock()

	err := t.srvHandler.Register(peerID)
	if err != nil {
		return err
	}

	var done bool
	for !done {
		select {
		case cu, more := <-peerCircuitUpdateQueue:
			if more {
				err := SendUpdate(cu, stream)
				if err != nil {
					done = true
				}
			} else {
				done = true
			}
		case <-t.transportDone:
			done = true
		case <-stream.Context().Done():
			done = true
		}
	}
	t.mPeers.Lock()
	close(peerCircuitUpdateQueue)
	peer.connected = false
	t.mPeers.Unlock()
	return t.srvHandler.Unregister(peerID)
}

type ComputeTransportHandler struct {
	*computeTransport
}

func (env *ComputeTransportHandler) GetCiphertext(ctx context.Context, ctr *api.CiphertextRequest) (*api.Ciphertext, error) {
	ct, err := env.srvHandler.GetCiphertext(ctx, pkg.CiphertextID(ctr.Id.CiphertextId))
	if err != nil {
		return nil, err
	}
	return ct.ToGRPC(), nil
}

func (env *ComputeTransportHandler) PutCiphertext(ctx context.Context, apict *api.Ciphertext) (*api.CiphertextID, error) {
	ct, err := pkg.NewCiphertextFromGRPC(apict)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext: %w", err)
	}
	err = env.srvHandler.PutCiphertext(ctx, *ct)
	if err != nil {
		return nil, err
	}
	return ct.ID.ToGRPC(), nil
}

func (env *computeTransport) PutShare(ctx context.Context, share *api.Share) (*api.Void, error) {
	return env.ShareTransport.PutShare(ctx, share)
}

func (env *computeTransport) StreamShares(stream api.ComputeService_StreamSharesServer) error {
	return env.ShareTransport.StreamShares(stream)
}

func (t *computeTransport) RegisterForComputeAt(ctx context.Context, peerID pkg.NodeID) (<-chan circuits.Update, int, error) {

	peer, exists := t.peers[peerID]
	if !exists {
		return nil, 0, fmt.Errorf("peer does not exists: %s", peerID)
	}

	if peer.cli == nil {
		return nil, 0, fmt.Errorf("peer is not connected: %s", peerID)
	}

	stream, err := peer.cli.RegisterForCompute(ctx, &api.Void{})
	if err != nil {
		panic(err)
	}

	present, err := readPresentFromStream(stream)
	if err != nil {
		return nil, present, err
	}

	descStream := make(chan circuits.Update)
	go func() {

		for {
			apicu, errRcv := stream.Recv()
			if errRcv != nil {
				close(descStream)
				if !errors.Is(errRcv, io.EOF) {
					fmt.Printf("error on server connection: %+v\n", errRcv) // TODO: transport logging
				}
				return
			}
			cu := circuits.Update{Signature: circuits.Signature{CircuitName: apicu.ComputeSignature.CircuitName, CircuitID: pkg.CircuitID(apicu.ComputeSignature.CircuitID)}, Status: circuits.Status(apicu.ComputeStatus)}
			if apicu.ProtocolUpdate != nil {
				pdesc := getProtocolDescFromAPI(apicu.ProtocolUpdate.ProtocolDescriptor)
				cu.StatusUpdate = &protocols.StatusUpdate{Descriptor: *pdesc, Status: protocols.Status(apicu.ProtocolUpdate.ProtocolStatus)}
			}

			descStream <- cu
			//log.Printf("received cu: %v", cu)
		}

	}()

	return descStream, present, nil
}

type computeServiceClientWrapper struct {
	api.ComputeServiceClient
}

func (scw *computeServiceClientWrapper) StreamShares(ctx context.Context, opts ...grpc.CallOption) (ShareStreamClient, error) {
	return scw.ComputeServiceClient.StreamShares(ctx, opts...)
}
