package setup

import (
	"context"
	"fmt"
	"log"

	"google.golang.org/grpc/metadata"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/node"
	"github.com/ldsec/helium/pkg/protocols"
	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/tuneinsight/lattigo/v3/drlwe"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type SetupService struct {
	*node.Node
	*api.UnimplementedSetupServiceServer

	peers map[pkg.NodeID]api.SetupServiceClient

	protocols map[pkg.ProtocolID]protocols.Interface
	aggTasks  chan AggregateTask
}

type ProtocolMap []protocols.Descriptor

func NewSetupService(n *node.Node) (s *SetupService, err error) {
	s = new(SetupService)
	s.Node = n
	s.protocols = make(map[pkg.ProtocolID]protocols.Interface)
	s.aggTasks = make(chan AggregateTask, 1024)
	s.peers = make(map[pkg.NodeID]api.SetupServiceClient)
	if n.IsFullNode() {
		n.RegisterService(&api.SetupService_ServiceDesc, s)
	}
	return s, nil
}

// Connect creates the grpc connections to the given nodes (represented by their pkg.NodeID's in the map dialers).
// These connections are used to intialised the api.SetupServiceClient instances of the nodes (stored in peers).
func (s *SetupService) Connect() {
	for peerID, peerConn := range s.Conns() {
		s.peers[peerID] = api.NewSetupServiceClient(peerConn)
	}
}

// Execute executes the ProtocolFetchShareTasks of s. These tasks consist in retrieving the share from each peer in the
// protocol and aggregating the shares.
func (s *SetupService) Execute() error {

	log.Printf("Node %s | started Execute with protocols %v \n", s.ID(), s.protocols)

	// fetches the shares of all full nodes
	for aggTask := range s.aggTasks {
		err := s.ExecuteAggTask(&aggTask)
		if err != nil {
			log.Printf("Node %s | failed to execute agg tast: %v\n", s.ID(), err)
			return err
		}
	}

	selfID := s.Node.ID()

	// waits for all aggregated shares to be ready
	for _, proto := range s.protocols {
		if proto.Desc().Aggregator == s.ID() {
			_, err := proto.GetShare(protocols.ShareRequest{AggregateFor: proto.Desc().Participants})
			if err != nil {
				log.Printf("Node %s | [%s]: get share error -- %v\n", selfID, proto.Desc().Type, err)
			}
		} else if !s.Node.HasAddress() {
			// temporary till RKG works
			share, err := proto.GetShare(protocols.ShareRequest{AggregateFor: []pkg.NodeID{selfID}, Round: uint64(1)})

			if err != nil {
				log.Printf("Node %s | [%s] failed to get share: %v\n", selfID, proto.Desc().Type, err)
				return err
			}
			log.Printf("Node %s | [%s] my share is %v\n", selfID, proto.Desc().Type, share)

			// send share to the aggregator - in this case the cloud

			// get cloud instance
			helper, err := s.Node.GetPeer(proto.Desc().Aggregator)
			if err != nil {
				log.Printf("Node %s | [%s] peer error: %v", selfID, proto.Desc().Type, err)
			}

			// todo - encapsulate this logic
			ctx := metadata.NewOutgoingContext(context.Background(),
				metadata.Pairs("session_id", "test-session", "sender_id", string(selfID)))
			cloudConn, err := s.PeerConn(helper.ID())
			if err != nil {
				log.Printf("Node %s | [%s] peer error: %v", selfID, proto.Desc().Type, err)
			}

			protoID := &api.ProtocolID{ProtocolID: (&api.ProtocolDescriptor{Type: proto.Desc().Type}).String()}
			apiShare, err := share.Share().MarshalBinary()
			if err != nil {
				return err
			}

			var one uint64 = 1
			var two uint64 = 2

			_, err = cloudConn.PutShare(ctx, &api.Share{ProtocolID: protoID, Share: apiShare, Round: &one})
			if err != nil {
				return err
			}

			if proto.Desc().Type == api.ProtocolType_RKG {
				log.Printf("Node %s | [%s] starting round %d", selfID, proto.Desc().Type, two)

				participants := make([]*api.NodeID, len(proto.Desc().Participants))
				for i, nodeID := range proto.Desc().Participants {
					participants[i] = &api.NodeID{NodeId: string(nodeID)}
				}

				// R2: get agg share
				aggR1, err := cloudConn.GetShare(ctx, &api.ShareRequest{ProtocolID: protoID, Round: &one, AggregateFor: participants})
				if err != nil {
					log.Printf("Node %s | [%s] agg share error: %v", selfID, proto.Desc().Type, err)
					return err
				}
				log.Printf("agg share: %v", len(aggR1.Share))

				var aggShareR1 drlwe.RKGShare
				err = aggShareR1.UnmarshalBinary(aggR1.Share)
				if err != nil {
					log.Printf("Node %s | [%s] failed to unmarshal share: %v", selfID, proto.Desc().Type, err)
					return err
				}

				apiShare, err = aggShareR1.MarshalBinary()
				if err != nil {
					log.Printf("Node %s | [%s] failed to marshall share 2: %v", selfID, proto.Desc().Type, err)
					return err
				}

				share2, err := proto.GetShare(protocols.ShareRequest{AggregateFor: []pkg.NodeID{selfID}, Round: two, Previous: apiShare})
				if err != nil {
					log.Printf("Node %s | [%s] get share 2: %v", selfID, proto.Desc().Type, err)
					return err
				}
				log.Printf("share 2: %v", share2)

				apiShare, err = share2.Share().MarshalBinary()
				if err != nil {
					log.Printf("Node %s | [%s] failed to marshall share: %v", selfID, proto.Desc().Type, err)
					return err
				}

				_, err = cloudConn.PutShare(ctx, &api.Share{ProtocolID: protoID, Share: apiShare, Round: &two})
				if err != nil {
					return err
				}
			}
		}
	}

	log.Printf("Node %s | execute returned\n", s.ID())
	return nil
}

func (s *SetupService) LoadProtocolMap(session *pkg.Session, pm ProtocolMap) error {
	taskCount := 0
	for _, protoDesc := range pm {

		proto, err := protocols.New(protoDesc, session)
		if err != nil {
			return err
		}

		protID := pkg.ProtocolID(api.ProtocolID{ProtocolID: (&api.ProtocolDescriptor{Type: proto.Desc().Type}).String()}.ProtocolID) // TODO: simplify and generalize protocol ID scheme

		s.protocols[protID] = proto
		if proto.Desc().Type == api.ProtocolType_SKG || proto.Desc().Aggregator == s.ID() {
			p := proto
			aggTask := AggregateTask{proto, make([]FetchShareTasks, 0, len(p.Required(1)))}
			for peer := range p.Required(1) {
				task := FetchShareTasks{Protocol: proto, ShareRequest: protocols.ShareRequest{ProtocolID: protID, From: s.ID(), To: peer, AggregateFor: []pkg.NodeID{peer}, Round: 1}}
				aggTask.fetchTasks = append(aggTask.fetchTasks, task)
			}
			s.aggTasks <- aggTask
			taskCount++

			if proto.Desc().Type == api.ProtocolType_RKG {
				aggTask := AggregateTask{proto, make([]FetchShareTasks, 0, len(p.Required(2)))}
				for peer := range p.Required(2) {
					task := FetchShareTasks{Protocol: proto, ShareRequest: protocols.ShareRequest{ProtocolID: protID, From: s.ID(), To: peer, AggregateFor: []pkg.NodeID{peer}, Round: 2}}
					aggTask.fetchTasks = append(aggTask.fetchTasks, task)
				}
				s.aggTasks <- aggTask
				taskCount++
			}
		}
	}

	log.Printf("Node %s | has %d fetch tasks\n", s.ID(), taskCount)
	close(s.aggTasks)

	return nil
}

func (s *SetupService) GetShare(ctx context.Context, req *api.ShareRequest) (*api.Share, error) {
	_, exists := s.GetSessionFromIncomingContext(ctx) // TODO assumes a single session for now
	if !exists {
		return nil, status.Errorf(codes.InvalidArgument, "invalid session id \"%s\"", pkg.SessionIDFromIncomingContext(ctx))
	}

	if req.ProtocolID == nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid protocol id: %s", req.ProtocolID)
	}

	proto, exists := s.protocols[pkg.ProtocolID(req.ProtocolID.ProtocolID)]
	if !exists {
		return nil, status.Errorf(codes.Unknown, "unknown protocol: %s", pkg.ProtocolID(req.ProtocolID.ProtocolID))
	}

	protoDesc := proto.Desc()

	sreq := protocols.ShareRequest{
		ProtocolID: pkg.ProtocolID(req.ProtocolID.ProtocolID),
		From:       pkg.NodeID(pkg.SenderIDFromIncomingContext(ctx)),
		To:         s.ID(),
	}
	if req.Round != nil {
		sreq.Round = *req.Round
	}
	if req.Previous != nil {
		sreq.Previous = req.Previous.Share
	}
	sreq.AggregateFor = make([]pkg.NodeID, len(req.AggregateFor))
	for i, nodeId := range req.AggregateFor {
		sreq.AggregateFor[i] = pkg.NodeID(nodeId.GetNodeId())
	}

	log.Printf("Node %s | got request from %s - GET [type: %s round: %d, previous: %v, aggregate_for: %v, no_data: %v]\n", s.ID(), pkg.SenderIDFromIncomingContext(ctx), protoDesc.Type, sreq.Round, sreq.Previous != nil, req.AggregateFor, req.GetNoData())

	share, err := proto.GetShare(sreq)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	shareBytes, err := share.Share().MarshalBinary()
	if err != nil {
		return nil, err
	}

	return &api.Share{ProtocolID: req.ProtocolID, Share: shareBytes, Round: req.Round}, nil
}

func (s *SetupService) PutShare(ctx context.Context, share *api.Share) (*api.Void, error) {
	_, exists := s.GetSessionFromIncomingContext(ctx)
	if !exists {
		return nil, status.Errorf(codes.InvalidArgument, "invalid session id \"%s\"", pkg.SessionIDFromIncomingContext(ctx))
	}

	proto, exists := s.protocols[pkg.ProtocolID(share.ProtocolID.ProtocolID)]
	if !exists {
		return nil, status.Errorf(codes.Unknown, "unknown protocol: %s", share.ProtocolID.ProtocolID)
	}

	protoDesc := proto.Desc()

	proptoShare, err := proto.GetShare(protocols.ShareRequest{AggregateFor: nil})
	if err != nil {
		return nil, err
	}

	err = proptoShare.Share().UnmarshalBinary(share.Share)
	if err != nil {
		log.Printf("failed to unmarshall share: %v", err)
		return nil, err
	}
	senderID := pkg.NodeID(pkg.SenderIDFromIncomingContext(ctx))
	proptoShare.AggregateFor().Add(senderID)

	_, err = proto.PutShare(proptoShare)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	var round string
	if share.Round != nil {
		round = fmt.Sprintf(" round: %d", *share.Round)
	}

	log.Printf("%s - PUT [type: %s%s]\n", pkg.SenderIDFromIncomingContext(ctx), protoDesc.Type, round)

	return &api.Void{}, nil
}

func (s *SetupService) PeerConn(id pkg.NodeID) (api.SetupServiceClient, error) {
	c := s.peers[id]
	if c != nil {
		return c, nil
	}
	return nil, fmt.Errorf("peer not found %s", id)
}
