package compute

import (
	"context"
	"fmt"
	"log"

	"github.com/google/uuid"
	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/node"
	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/ldsec/helium/pkg/utils"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ComputeService struct {
	*node.Node
	*api.UnimplementedComputeServiceServer

	peers map[pkg.NodeID]api.ComputeServiceClient
}

func NewComputeService(n *node.Node) (s *ComputeService, err error) {
	s = new(ComputeService)
	s.Node = n

	s.peers = make(map[pkg.NodeID]api.ComputeServiceClient)

	if n.HasAddress() {
		n.RegisterService(&api.ComputeService_ServiceDesc, s)
	}
	return s, nil
}

// Connect creates the grpc connections to the given nodes (represented by their pkg.NodeID's in the map dialers). These connections are used to intialised the api.ComputeServiceClient instances of the nodes (stored in peers).
func (s *ComputeService) Connect() {
	for peerID, peerConn := range s.Conns() {
		s.peers[peerID] = api.NewComputeServiceClient(peerConn)
	}
}

func (s *ComputeService) GetCiphertext(ctx context.Context, ctr *api.CiphertextRequest) (*api.Ciphertext, error) {

	ictx := utils.Context{Context: ctx}
	sess, exists := s.GetSessionFromID(ictx.SessionID())
	if !exists {
		return nil, status.Errorf(codes.InvalidArgument, "invalid session id")
	}

	id := pkg.CiphertextID(ctr.Id.CiphertextId)

	ct, exists := sess.Load(id)
	if !exists {
		return nil, status.Errorf(codes.NotFound, "ciphertext not found")
	}

	ctMsg := ct.ToGRPC()

	log.Printf("Node %s | got request from %s - GET %s \n", s.ID(), ictx.SenderID(), id)

	return &ctMsg, nil
}

func (s *ComputeService) PutCiphertext(ctx context.Context, ct *api.Ciphertext) (ctId *api.CiphertextID, err error) {
	ictx := utils.Context{Context: ctx}
	sess, exists := s.GetSessionFromID(ictx.SessionID())
	if !exists {
		return nil, status.Errorf(codes.InvalidArgument, "invalid session id")
	}

	var c *pkg.Ciphertext
	c, err = pkg.NewCiphertextFromGRPC(ct)
	if err != nil {
		return
	}

	if c.ID == "" {
		c.ID = pkg.CiphertextID(uuid.New().String())
	}

	err = sess.Store(*c)
	if err != nil {
		return nil, status.Errorf(codes.Internal, fmt.Sprintf("%s", err))
	}

	log.Printf("Node %s | got request from %s - PUT %s \n", s.ID(), ictx.SenderID(), c.ID)

	return &api.CiphertextID{CiphertextId: string(c.ID)}, nil
}
