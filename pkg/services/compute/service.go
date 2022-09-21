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

	circuits map[pkg.CircuitID]pkg.LocalCircuit

	peers map[pkg.NodeID]api.ComputeServiceClient
}

func NewComputeService(n *node.Node) (s *ComputeService, err error) {
	s = new(ComputeService)
	s.Node = n

	s.circuits = make(map[pkg.CircuitID]pkg.LocalCircuit)

	s.circuits["ComponentWiseProduct4P"] = pkg.ComponentWiseProduct4P

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

type CircuitDesc struct {
	ID      pkg.CircuitID
	Session pkg.SessionID
}

func (s *ComputeService) LoadCircuit(cd CircuitDesc) error {
	// TODO
	return nil
}

func (s *ComputeService) Execute(cd CircuitDesc, localOps ...pkg.Operand) error {

	// Idea: full nodes will resolve compute all session and local ciphertext by either resolving the inputs or waiting for them.
	// Light node isolate their inputs and send them to the know full node(s?)/delegates(s?)
	// TODO: decouple ciphertext store and PUT/GET from session, there should be a Circuit-level entity that manage them
	// after LoadCircuit, each node knows what circuit needs what input and knows how to respond to queries (potentially by blocking)

	return status.Errorf(codes.Unimplemented, "execute is not implemented yet")
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

	// TODO checks if input is pending for a circuit

	// stores the ciphertext
	err = sess.Store(*c)
	if err != nil {
		return nil, status.Errorf(codes.Internal, fmt.Sprintf("%s", err))
	}

	log.Printf("Node %s | got request from %s - PUT %s \n", s.ID(), ictx.SenderID(), c.ID)

	return &api.CiphertextID{CiphertextId: string(c.ID)}, nil
}
