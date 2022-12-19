package services

import (
	"context"
	"fmt"
	"log"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/protocols"
	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/ldsec/helium/pkg/utils"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ProtocolClient interface {
	GetShare(ctx context.Context, in *api.ShareRequest, opts ...grpc.CallOption) (*api.Share, error)
	PutShare(ctx context.Context, in *api.Share, opts ...grpc.CallOption) (*api.Void, error)
}

type Environment struct {
	self                  pkg.NodeID // TODO pass through context ?
	peers                 map[pkg.NodeID]ProtocolClient
	outgoingShares        chan protocols.Share
	queries               chan protocols.ShareQuery // TODO hide behind interface ?
	incomingShares        map[pkg.ProtocolID]chan protocols.Share
	incomingSharesQueries map[pkg.ProtocolID]chan protocols.ShareQuery
	protocolTypes         map[pkg.ProtocolID]protocols.Type
}

type ProtocolEnvironment struct {
	*Environment
	incomingShares        chan protocols.Share
	incomingSharesQueries chan protocols.ShareQuery
}

func NewEnvironment(id pkg.NodeID) (*Environment, error) {
	pc := new(Environment)
	pc.self = id
	pc.outgoingShares = make(chan protocols.Share, 32) // TODO sizing
	pc.queries = make(chan protocols.ShareQuery)
	pc.peers = make(map[pkg.NodeID]ProtocolClient)
	pc.incomingShares = make(map[pkg.ProtocolID]chan protocols.Share)
	pc.incomingSharesQueries = make(map[pkg.ProtocolID]chan protocols.ShareQuery)
	pc.protocolTypes = make(map[pkg.ProtocolID]protocols.Type)
	return pc, nil
}

func (env *Environment) RegisterProtocol(pid pkg.ProtocolID, pType protocols.Type) error {
	if _, exists := env.incomingShares[pid]; exists {
		return fmt.Errorf("protocol with id %s already registered", pid)
	}
	env.incomingShares[pid] = make(chan protocols.Share, 32) // TODO sizing
	env.incomingSharesQueries[pid] = make(chan protocols.ShareQuery, 32)
	env.protocolTypes[pid] = pType
	return nil
}

func (env *Environment) EnvironmentForProtocol(pid pkg.ProtocolID) *ProtocolEnvironment {
	return &ProtocolEnvironment{Environment: env, incomingShares: env.incomingShares[pid], incomingSharesQueries: env.incomingSharesQueries[pid]} // TODO check PID
}

func (env *Environment) IncomingShare(s protocols.Share) error {
	if ic, exists := env.incomingShares[s.ProtocolID]; exists {
		ic <- s
		return nil
	}
	return fmt.Errorf("no such protocol: %s", s.ProtocolID)
}

func (env *Environment) IncomingShareQuery(sq protocols.ShareQuery) error {
	if ic, exists := env.incomingSharesQueries[sq.ProtocolID]; exists {
		ic <- sq
		return nil
	}
	return fmt.Errorf("no such protocol: %s", sq.ProtocolID)
}

// Connect creates the grpc connections to the given nodes (represented by their pkg.NodeID's in the map dialers).
// These connections are used to intialised the api.SetupServiceClient instances of the nodes (stored in peers).
func (env *Environment) Connect(peers map[pkg.NodeID]ProtocolClient) {
	for peerID, peerCli := range peers {
		env.peers[peerID] = peerCli
	}
}

func (env *Environment) Run(ctx context.Context) {
	go func() {
		for share := range env.outgoingShares {
			err := env.sendShare(ctx, share)
			if err != nil {
				panic(err)
			}

		}
	}()

	go func() {
		for sq := range env.queries {
			err := env.fetchShare(ctx, sq)
			if err != nil {
				panic(err)
			}
		}
	}()
}

func (env *Environment) ShareQuery(sq protocols.ShareQuery) {
	env.queries <- sq
}

func (env *Environment) OutgoingShares() chan<- protocols.Share {
	return env.outgoingShares
}

func (env *ProtocolEnvironment) IncomingShares() <-chan protocols.Share {
	return env.incomingShares
}

func (env *ProtocolEnvironment) IncomingShareQueries() <-chan protocols.ShareQuery {
	return env.incomingSharesQueries
}

func (env *Environment) PutShare(ctx context.Context, share *api.Share) (*api.Void, error) { // TODO NEXT: Move in service.Environment

	pid := pkg.ProtocolID(share.ProtocolID.GetProtocolID()) // TODO passed through context ?
	pType, exists := env.protocolTypes[pid]
	if !exists {
		return nil, status.Errorf(codes.Internal, "unknown protocol id %s", pid)
	}

	senderID := pkg.SenderIDFromIncomingContext(ctx)
	sd := protocols.ShareDescriptor{ProtocolID: pid, From: senderID, To: env.self, Round: 1, AggregateFor: utils.NewSingletonSet(senderID)} // TODO assumes share is "from" the sender
	proptoShare := protocols.Share{MHEShare: pType.Share(), ShareDescriptor: sd}
	err := proptoShare.MHEShare.UnmarshalBinary(share.Share)
	if err != nil {
		log.Printf("failed to unmarshall share: %v", err)
		return nil, err
	}

	err = env.IncomingShare(proptoShare)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	log.Printf("%s PUT from %s [type: %s]\n", env.self, pkg.SenderIDFromIncomingContext(ctx), pType)

	return &api.Void{}, nil
}

func (env *Environment) GetShare(ctx context.Context, req *api.ShareRequest) (*api.Share, error) { // TODO NEXT: Move in service.Environment

	pid := pkg.ProtocolID(req.ProtocolID.ProtocolID)
	pType, exists := env.protocolTypes[pid]
	if !exists {
		return nil, status.Errorf(codes.InvalidArgument, "protocol id %s does not exist", pid)
	}

	sd := protocols.ShareDescriptor{
		ProtocolID: pid,
		From:       env.self,
		To:         pkg.SenderIDFromIncomingContext(ctx),
	}
	if req.Round != nil {
		sd.Round = *req.Round
	}

	sd.AggregateFor = utils.NewEmptySet[pkg.NodeID]()
	for _, nodeID := range req.AggregateFor {
		sd.AggregateFor.Add(pkg.NodeID(nodeID.GetNodeId()))
	}

	logLine := fmt.Sprintf("Node %s | got request from %s - GET [type: %s round: %d, previous: %v, aggregate_for: %v, no_data: %v]:", env.self, pkg.SenderIDFromIncomingContext(ctx), pType, sd.Round, req.Previous != nil, req.AggregateFor, req.GetNoData())
	res := make(chan protocols.Share, 1)
	sq := protocols.ShareQuery{ShareDescriptor: sd, Result: res}
	err := env.IncomingShareQuery(sq)
	if err != nil {
		log.Println(logLine, err)
		return nil, err
	}

	share := <-res
	shareBytes, err := share.MHEShare.MarshalBinary()
	if err != nil {
		log.Println(logLine, err)
		return nil, err
	}

	log.Println(logLine, "OK")
	return &api.Share{ProtocolID: req.ProtocolID, Share: shareBytes, Round: req.Round}, nil
}

func (env *Environment) sendShare(ctx context.Context, share protocols.Share) error {

	outCtx := pkg.GetOutgoingContext(ctx, env.self)

	targetConn, exists := env.peers[share.To]
	if !exists {
		return fmt.Errorf("peer with id %s does not exist", share.To)
	}

	protoID := &api.ProtocolID{ProtocolID: string(share.ProtocolID)}

	shareBytes, err := share.MHEShare.MarshalBinary()
	if err != nil {
		return err
	}

	_, err = targetConn.PutShare(outCtx, &api.Share{ProtocolID: protoID, Share: shareBytes, Round: &share.Round})
	return err
}

func (env *Environment) fetchShare(ctx context.Context, sq protocols.ShareQuery) error {

	sd := sq.ShareDescriptor

	if sd.From == env.self {
		return fmt.Errorf("should not GetShare a local share")
	}

	cli, hasCli := env.peers[sd.From]
	if !hasCli {
		return fmt.Errorf("trying to fetch share from an unconnected party")
	}

	log.Printf("Node %s | executing remote fetch: %v to %s\n", env.self, sd, sd.From)
	outCtx := pkg.GetOutgoingContext(ctx, env.self)

	aggFor := make([]*api.NodeID, 0, len(sd.AggregateFor))
	for nodeID := range sd.AggregateFor {
		aggFor = append(aggFor, &api.NodeID{NodeId: string(nodeID)})
	}

	// makes the request to the peer
	sr := &api.ShareRequest{ProtocolID: &api.ProtocolID{ProtocolID: string(sd.ProtocolID)}, Round: &sd.Round, AggregateFor: aggFor}
	peerShare, err := cli.GetShare(outCtx, sr)
	if err != nil {
		return err
	}

	share := protocols.Share{ShareDescriptor: sd, MHEShare: sd.Share()}
	share.AggregateFor = sd.AggregateFor.Copy()

	err = share.MHEShare.UnmarshalBinary(peerShare.Share)
	if err != nil {
		return err
	}

	sq.Result <- share
	return err
}
