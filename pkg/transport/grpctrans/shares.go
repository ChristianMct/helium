package grpctrans

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/protocols"
	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/ldsec/helium/pkg/utils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type ShareStream interface {
	Send(*api.Share) error
	Recv() (*api.Share, error)
}

type ShareStreamClient interface {
	ShareStream
	grpc.ClientStream
}

type ShareStreamServer interface {
	ShareStream
	grpc.ServerStream
}

type ShareTransportClient interface {
	PutShare(ctx context.Context, in *api.Share, opts ...grpc.CallOption) (*api.Void, error)
	StreamShares(ctx context.Context, opts ...grpc.CallOption) (ShareStreamClient, error)
}

type ShareTransport struct {
	*Transport

	outgoingShares chan protocols.Share
	incomingShares chan protocols.Share

	isLight bool
	peers   map[pkg.NodeID]*struct {
		c   chan protocols.Share
		cli ShareTransportClient
	}
}

func (t *Transport) NewShareTransport() *ShareTransport {
	st := new(ShareTransport)
	st.Transport = t
	st.outgoingShares = make(chan protocols.Share)
	st.incomingShares = make(chan protocols.Share)
	st.peers = make(map[pkg.NodeID]*struct {
		c   chan protocols.Share
		cli ShareTransportClient
	})
	for _, nid := range st.nodeList {
		st.peers[nid.NodeID] = &struct {
			c   chan protocols.Share
			cli ShareTransportClient
		}{c: make(chan protocols.Share)}
		if nid.NodeID == t.id {
			st.isLight = nid.NodeAddress == ""
		}
	}
	return st
}

func (st *ShareTransport) Connect(clis map[pkg.NodeID]ShareTransportClient) error {
	for peerID, peerCli := range clis {
		if !st.isClientFor(peerID) {
			continue
		}
		var stream ShareStreamClient
		var err error
		st.peers[peerID].cli = peerCli
		outCtx := pkg.GetOutgoingContext(context.Background(), st.id)
		stream, err = st.peers[peerID].cli.StreamShares(outCtx)
		if err != nil {
			panic(err)
		}
		_, err = stream.Header()
		if err != nil {
			panic(err)
		}

		ctx := stream.Context()
		if ctx.Err() != nil {
			panic(ctx.Err())
		}

		go func() {
			if errStream := st.handleShareStream(peerID, stream, st.incomingShares, st.peers[peerID].c); errStream != nil {
				log.Printf("%s | share stream closed with error: %s", st.id, errStream)
			}
		}()
		log.Printf("%s | opened stream with %v\n", st.id, peerID)
	}
	return nil
}

func (st *ShareTransport) isClientFor(peerID pkg.NodeID) bool {
	return st.isLight || st.id < peerID
}

func (st *ShareTransport) Run() {
	go func() {
		for share := range st.outgoingShares {
			for _, t := range share.To {
				if t == st.id {
					st.incomingShares <- share
					continue
				}
				peer, exists := st.peers[t]
				if !exists {
					panic(fmt.Errorf("not connected with peer id %s", t))
				}

				peer.c <- share
			}
		}
	}()
}

func (st *ShareTransport) StreamShares(stream ShareStreamServer) error {

	peerID := pkg.SenderIDFromIncomingContext(stream.Context())
	if peerID == "" {
		panic(fmt.Errorf("client must specify node id for stream"))
	}

	peer, exists := st.peers[peerID]
	if !exists {
		return fmt.Errorf("peer with id %s does not exist", peerID)
	}

	if err := stream.SendHeader(metadata.MD{}); err != nil {
		return fmt.Errorf("could not send share stream header: %w", err)
	}

	done := make(chan error)
	go func() {
		done <- st.handleShareStream(peerID, stream, st.incomingShares, peer.c)
	}()

	return <-done
}

func (st *ShareTransport) OutgoingShares() chan<- protocols.Share {
	return st.outgoingShares
}

func (st *ShareTransport) IncomingShares() <-chan protocols.Share {
	return st.incomingShares
}

func (st *ShareTransport) handleShareStream(peerID pkg.NodeID, stream ShareStream, incoming, outgoing chan protocols.Share) error {
	streamErr := make(chan error)
	go func() {
		for outShare := range outgoing {
			s, err := getAPIShare(&outShare)
			if err != nil {
				log.Printf("error while sending share %v:\n\t %v", outShare, err)
				continue
			}
			err = stream.Send(s)
			if err != nil {
				log.Printf("error while sending share %v:\n\t %v", outShare, err)
				streamErr <- err
				return
			}
		}
	}()

	go func() {
		for {
			incShare, err := stream.Recv()
			if err != nil {
				if !errors.Is(err, io.EOF) && status.Code(err) != codes.Canceled {
					log.Printf("%s | error while receiving share: %v", st.id, err)
				}
				break
			}

			s, err := getShareFromAPI(incShare)
			if err != nil {
				panic(err)
			}
			incoming <- s
		}
	}()
	//log.Printf("%s | handling stream with %v\n", st.id, peerID)
	err := <-streamErr
	return err
}

func getAPIShare(s *protocols.Share) (*api.Share, error) {
	outShareBytes, err := s.MarshalBinary()
	if err != nil {
		return nil, err
	}
	apiShare := &api.Share{
		Desc: &api.ShareDescriptor{
			ProtocolID:   &api.ProtocolID{ProtocolID: string(s.ProtocolID)},
			ProtocolType: api.ProtocolType(s.Type),
			Round:        &s.Round,
			Sender:       &api.NodeID{NodeId: string(s.From)},
			Receivers:    make([]*api.NodeID, 0, len(s.To)),
			AggregateFor: make([]*api.NodeID, 0, len(s.AggregateFor)),
		},
		Share: outShareBytes,
	}
	for _, nID := range s.To {
		apiShare.Desc.Receivers = append(apiShare.Desc.Receivers, &api.NodeID{NodeId: string(nID)})
	}
	for nID := range s.AggregateFor {
		apiShare.Desc.AggregateFor = append(apiShare.Desc.AggregateFor, &api.NodeID{NodeId: string(nID)})
	}
	return apiShare, nil
}

func getShareFromAPI(s *api.Share) (protocols.Share, error) {
	desc := s.GetDesc()
	pID := pkg.ProtocolID(desc.GetProtocolID().GetProtocolID())
	pType := protocols.Type(desc.ProtocolType)
	share := pType.Share()
	if share == nil {
		return protocols.Share{}, fmt.Errorf("unknown share type: %s", pType)
	}
	ps := protocols.Share{
		ShareDescriptor: protocols.ShareDescriptor{
			ProtocolID:   pID,
			Type:         pType,
			Round:        desc.GetRound(),
			From:         pkg.NodeID(desc.GetSender().GetNodeId()),
			To:           make([]pkg.NodeID, 0, len(desc.GetReceivers())),
			AggregateFor: make(utils.Set[pkg.NodeID]),
		},
		MHEShare: share,
	}
	for _, nid := range desc.GetReceivers() {
		ps.To = append(ps.To, pkg.NodeID(nid.NodeId))
	}
	for _, nid := range desc.AggregateFor {
		ps.AggregateFor.Add(pkg.NodeID(nid.NodeId))
	}

	err := ps.MHEShare.UnmarshalBinary(s.GetShare())
	if err != nil {
		return protocols.Share{}, err
	}
	return ps, nil
}

func (st *ShareTransport) PutShare(ctx context.Context, share *api.Share) (*api.Void, error) {

	// pid := pkg.ProtocolID(share.Desc.ProtocolID.GetProtocolID()) // TODO passed through context ?
	// pType, exists := env.protocolTypes[pid]
	// if !exists {
	// 	return nil, status.Errorf(codes.Internal, "unknown protocol id %s", pid)
	// }

	// senderID := pkg.SenderIDFromIncomingContext(ctx)
	// sd := protocols.ShareDescriptor{ProtocolID: pid, From: senderID, To: env.self, Round: 1, AggregateFor: utils.NewSingletonSet(senderID)} // TODO assumes share is "from" the sender
	// proptoShare := protocols.Share{MHEShare: pType.Share(), ShareDescriptor: sd}
	// err := proptoShare.MHEShare.UnmarshalBinary(share.Share)
	// if err != nil {
	// 	log.Printf("failed to unmarshall share: %v", err)
	// 	return nil, err
	// }

	// err = env.IncomingShare(proptoShare)
	// if err != nil {
	// 	return nil, status.Errorf(codes.Internal, err.Error())
	// }

	// log.Printf("%s PUT from %s [type: %s]\n", env.self, pkg.SenderIDFromIncomingContext(ctx), pType)

	// return &api.Void{}, nil
	return nil, status.Errorf(codes.Unimplemented, "unimplemented by this transport")
}

func (st *ShareTransport) GetShare(ctx context.Context, desc *api.ShareDescriptor) (*api.Share, error) {

	// pid := pkg.ProtocolID(req.ShareDescriptor.ProtocolID.ProtocolID)
	// pType, exists := env.protocolTypes[pid]
	// if !exists {
	// 	return nil, status.Errorf(codes.InvalidArgument, "protocol id %s does not exist", pid)
	// }

	// sd := protocols.ShareDescriptor{
	// 	ProtocolID: pid,
	// 	From:       env.self,
	// 	To:         pkg.SenderIDFromIncomingContext(ctx),
	// }
	// if req.ShareDescriptor.Round != nil {
	// 	sd.Round = *req.ShareDescriptor.Round
	// }

	// sd.AggregateFor = utils.NewEmptySet[pkg.NodeID]()
	// for _, nodeID := range req.ShareDescriptor.AggregateFor {
	// 	sd.AggregateFor.Add(pkg.NodeID(nodeID.GetNodeId()))
	// }

	// logLine := fmt.Sprintf("Node %s | got request from %s - GET [type: %s round: %d, aggregate_for: %v, no_data: %v]:", env.self, pkg.SenderIDFromIncomingContext(ctx), pType, sd.Round, req.ShareDescriptor.AggregateFor, req.GetNoData())
	// res := make(chan protocols.Share, 1)
	// sq := protocols.ShareQuery{ShareDescriptor: sd, Result: res}
	// err := env.IncomingShareQuery(sq)
	// if err != nil {
	// 	log.Println(logLine, err)
	// 	return nil, err
	// }

	// share := <-res
	// shareBytes, err := share.MHEShare.MarshalBinary()
	// if err != nil {
	// 	log.Println(logLine, err)
	// 	return nil, err
	// }

	// log.Println(logLine, "OK")
	// return &api.Share{Desc: req.ShareDescriptor, Share: shareBytes}, nil
	return nil, status.Errorf(codes.Unimplemented, "unimplemented by this transport")
}
