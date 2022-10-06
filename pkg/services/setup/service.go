package setup

import (
	"context"
	"fmt"
	"google.golang.org/grpc/metadata"
	"log"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/node"
	pkg "github.com/ldsec/helium/pkg/session"

	"github.com/tuneinsight/lattigo/v3/drlwe"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type SetupService struct {
	*node.Node
	*api.UnimplementedSetupServiceServer

	peers map[pkg.NodeID]api.SetupServiceClient

	protocols map[pkg.ProtocolID]ProtocolInt
	aggTasks  chan AggregateTask
}

type ProtocolDescriptor struct {
	Type         api.ProtocolType
	Args         map[string]string
	Aggregator   pkg.NodeID
	Participants []pkg.NodeID
}

type ShareRequest struct {
	pkg.ProtocolID
	From         pkg.NodeID
	To           pkg.NodeID
	Round        uint64
	Previous     []byte
	AggregateFor []pkg.NodeID
	NoData       bool
}

func (s ShareRequest) String() string {
	return fmt.Sprintf("ShareRequest[protocol_id: %s from: %s to: %s has_previous: %v]", s.ProtocolID, s.From, s.To, len(s.Previous) > 0)
}

type ProtocolMap []ProtocolDescriptor

func NewSetupService(n *node.Node) (s *SetupService, err error) {
	s = new(SetupService)
	s.Node = n
	s.protocols = make(map[pkg.ProtocolID]ProtocolInt)
	s.aggTasks = make(chan AggregateTask, 1024)
	s.peers = make(map[pkg.NodeID]api.SetupServiceClient)
	if n.HasAddress() {
		n.RegisterService(&api.SetupService_ServiceDesc, s)
	}
	return s, nil
}

// Connect creates the grpc connections to the given nodes (represented by their pkg.NodeID's in the map dialers). These connections are used to intialised the api.SetupServiceClient instances of the nodes (stored in peers).
func (s *SetupService) Connect() {
	for peerID, peerConn := range s.Conns() {
		s.peers[peerID] = api.NewSetupServiceClient(peerConn)
	}
}

// Execute executes the ProtocolFetchShareTasks of s. These tasks consist in retrieving the share from each peer in the protocol and aggregating the shares.
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
		if proto.Descriptor().Aggregator == s.ID() {
			_, err := proto.GetShare(ShareRequest{AggregateFor: proto.Descriptor().Participants})
			if err != nil {
				log.Printf("%s get share: node %s -- %v\n", proto.Descriptor().Type, selfID, err)
				//return err
			}
		} else if !s.Node.HasAddress() {

			share, err := proto.GetShare(ShareRequest{AggregateFor: []pkg.NodeID{selfID}})

			if err != nil {
				log.Printf("Node %s | [%s] failed to get share: %v\n", selfID, proto.Descriptor().Type, err)
				return err
			}
			log.Printf("Node %s | [%s] my share is %v\n", selfID, proto.Descriptor().Type, share)

			// send share to the aggregator - in this case the cloud

			// get cloud instance
			helper, err := s.Node.HelperPeer()
			if err != nil {
				log.Printf("Node %s | [%s] peer error: %v", selfID, proto.Descriptor().Type, err)
			}

			// todo - encapsulate this logic
			ctx := metadata.NewOutgoingContext(context.Background(),
				metadata.Pairs("session_id", "test-session", "node_id", string(selfID)))
			cloudConn := s.peers[helper.ID()] // todo: distinction between node.peers and node.Peers()

			protoID := &api.ProtocolID{ProtocolID: (&api.ProtocolDescriptor{Type: proto.Descriptor().Type}).String()}
			apiShare, err := share.Share().MarshalBinary()
			if err != nil {
				return err
			}
			putShare, err := cloudConn.PutShare(ctx, &api.Share{ProtocolID: protoID, Share: apiShare})
			if err != nil {
				return err
			}
			log.Printf("Node %s | [%s] put share %v", selfID, proto.Descriptor().Type, putShare)

		}
	}

	log.Printf("Node %s | execute returned\n", s.ID())
	return nil
}

func (s *SetupService) LoadProtocolMap(session *pkg.Session, pm ProtocolMap) error {
	taskCount := 0
	for _, protoDesc := range pm {

		var protID api.ProtocolDescriptor
		var proto ProtocolInt
		switch protoDesc.Type {
		case api.ProtocolType_SKG:
			protID = api.ProtocolDescriptor{Type: api.ProtocolType_SKG}
			proto = &SKGProtocol{
				protocol:      protocol{ProtocolDescriptor: protoDesc, ID: pkg.ProtocolID(protID.String())},
				Thresholdizer: drlwe.NewThresholdizer(*session.Params),
			}
		case api.ProtocolType_CKG:
			protID = api.ProtocolDescriptor{Type: api.ProtocolType_CKG}
			proto = &CKGProtocol{
				protocol:    protocol{ProtocolDescriptor: protoDesc, ID: pkg.ProtocolID(protID.String())},
				CKGProtocol: *drlwe.NewCKGProtocol(*session.Params)}

		case api.ProtocolType_RTG:
			protID = api.ProtocolDescriptor{Type: api.ProtocolType_RTG}
			proto = &RTGProtocol{
				protocol:    protocol{ProtocolDescriptor: protoDesc, ID: pkg.ProtocolID(protID.String())},
				RTGProtocol: *drlwe.NewRTGProtocol(*session.Params),
			}
		case api.ProtocolType_RKG:
			protID = api.ProtocolDescriptor{Type: api.ProtocolType_RKG}
			proto = &RKGProtocol{
				protocol:    protocol{ProtocolDescriptor: protoDesc, ID: pkg.ProtocolID(protID.String())},
				RKGProtocol: *drlwe.NewRKGProtocol(*session.Params)}

		default:
			log.Println("unknown type", protoDesc.Type, "was skipped")
			continue
		}

		if err := proto.Init(protoDesc, session); err != nil {
			return err
		}

		s.protocols[pkg.ProtocolID(protID.String())] = proto
		if proto.Descriptor().Type == api.ProtocolType_SKG || proto.Descriptor().Aggregator == s.ID() {
			id := pkg.ProtocolID(protID.String())
			p := proto
			aggTask := AggregateTask{proto, make([]FetchShareTasks, 0, len(p.Required(1)))}
			for peer := range p.Required(1) {
				task := FetchShareTasks{Protocol: proto, ShareRequest: ShareRequest{ProtocolID: id, From: s.ID(), To: peer, AggregateFor: []pkg.NodeID{peer}, Round: 1}}
				aggTask.fetchTasks = append(aggTask.fetchTasks, task)
			}
			s.aggTasks <- aggTask
			taskCount++

			if proto.Descriptor().Type == api.ProtocolType_RKG {
				aggTask := AggregateTask{proto, make([]FetchShareTasks, 0, len(p.Required(2)))}
				for peer := range p.Required(2) {
					task := FetchShareTasks{Protocol: proto, ShareRequest: ShareRequest{ProtocolID: id, From: s.ID(), To: peer, AggregateFor: []pkg.NodeID{peer}, Round: 2}}
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
	ictx := pkg.Context{Context: ctx}
	_, exists := s.GetSessionFromID(ictx.SessionID()) // TODO assumes a single session for now
	if !exists {
		return nil, status.Errorf(codes.InvalidArgument, "invalid session id \"%s\"", ictx.SessionID())
	}

	if req.ProtocolID == nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid protocol id: %s", req.ProtocolID)
	}

	proto, exists := s.protocols[pkg.ProtocolID(req.ProtocolID.ProtocolID)]
	if !exists {
		return nil, status.Errorf(codes.Unknown, "unknown protocol: %s", pkg.ProtocolID(req.ProtocolID.ProtocolID))
	}

	protoDesc := proto.Descriptor()

	sreq := ShareRequest{
		ProtocolID: pkg.ProtocolID(req.ProtocolID.ProtocolID),
		From:       pkg.NodeID(ictx.SenderID()),
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

	log.Printf("Node %s | got request from %s - GET [type: %s round: %d, previous: %v, aggregate_for: %v, no_data: %v]\n", s.ID(), ictx.SenderID(), protoDesc.Type, sreq.Round, sreq.Previous != nil, req.AggregateFor, req.GetNoData())

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
	ictx := pkg.Context{Context: ctx}
	_, exists := s.GetSessionFromID(ictx.SessionID())
	if !exists {
		return nil, status.Errorf(codes.InvalidArgument, "invalid session id \"%s\"", ictx.SessionID())
	}

	proto, exists := s.protocols[pkg.ProtocolID(share.ProtocolID.ProtocolID)]
	if !exists {
		return nil, status.Errorf(codes.Unknown, "unknown protocol: %s", share.ProtocolID.ProtocolID)
	}

	protoDesc := proto.Descriptor()

	proptoShare, err := proto.GetShare(ShareRequest{AggregateFor: nil})
	if err != nil {
		return nil, err
	}

	proptoShare.Share().UnmarshalBinary(share.Share)
	senderID := pkg.NodeID(ictx.SenderID())
	proptoShare.AggregateFor().Add(senderID)

	_, err = proto.PutShare(proptoShare)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	var round string
	if share.Round != nil {
		round = fmt.Sprintf(" round: %d", *share.Round)
	}

	log.Printf("%s - PUT [type: %s%s]\n", ictx.SenderID(), protoDesc.Type, round)

	return &api.Void{}, nil
}
