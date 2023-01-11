package setup

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/node"
	"github.com/ldsec/helium/pkg/protocols"
	"github.com/ldsec/helium/pkg/services"
	pkg "github.com/ldsec/helium/pkg/session"
)

type Service struct {
	*node.Node
	*api.UnimplementedSetupServiceServer
	*services.Environment

	protocols map[pkg.ProtocolID]protocols.Instance
}

func NewSetupService(n *node.Node) (s *Service, err error) {
	s = new(Service)
	s.Node = n
	s.protocols = make(map[pkg.ProtocolID]protocols.Instance)
	if n.IsFullNode() {
		n.RegisterService(&api.SetupService_ServiceDesc, s)
	}
	s.Environment, err = services.NewEnvironment(s.ID())
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Service) Connect() {
	peers := make(map[pkg.NodeID]services.ProtocolClient)
	for peerID, peerConn := range s.Conns() {
		peers[peerID] = api.NewSetupServiceClient(peerConn)
	}
	s.Environment.Connect(peers)
}

// Execute executes the ProtocolFetchShareTasks of s. These tasks consist in retrieving the share from each peer in the
// protocol and aggregating the shares.
func (s *Service) Execute() error {

	log.Printf("Node %s | started Execute with protocols %v \n", s.ID(), s.protocols)

	sessID := pkg.SessionID("test-session") // TODO non-hardcoded session

	sess, exists := s.GetSessionFromID(sessID)
	if !exists {
		panic("test session does not exist")
	}

	ctx := pkg.NewContext(&sessID, nil)

	s.Environment.Run(ctx)

	wg := sync.WaitGroup{}
	for _, p := range s.protocols {
		wg.Add(1)
		p := p
		go func() {
			p.Run(ctx, sess, s.EnvironmentForProtocol(p.ID()))
			wg.Done()
		}()
	}

	wg.Wait()

	log.Printf("Node %s | execute returned\n", s.ID())
	return nil
}

func (s *Service) LoadSetupDescription(session *pkg.Session, sd Description) error {
	return s.LoadProtocolMap(session, GenProtoMap(sd, s.NodeList(), session.T, session.Nodes))
}

func (s *Service) LoadProtocolMap(session *pkg.Session, pm ProtocolMap) error {
	var rtgID uint64
	for _, protoDesc := range pm {

		pIDStr := protoDesc.Type.String()
		if protoDesc.Type == protocols.RTG {
			pIDStr = fmt.Sprintf("%s[%d]", pIDStr, rtgID)
			rtgID++
		}
		pid := pkg.ProtocolID(pIDStr)

		proto, err := protocols.NewProtocol(protoDesc, session, pid)
		if err != nil {
			return err
		}

		err = s.RegisterProtocol(pid, protoDesc.Type)
		if err != nil {
			return err
		}
		s.protocols[pid] = proto
	}
	return nil
}

func (s *Service) GetShare(ctx context.Context, req *api.ShareRequest) (*api.Share, error) { // TODO: why do we need this ?
	return s.Environment.GetShare(ctx, req)
}

func (s *Service) PutShare(ctx context.Context, share *api.Share) (*api.Void, error) { // TODO: why do we need this ?
	return s.Environment.PutShare(ctx, share)
}
