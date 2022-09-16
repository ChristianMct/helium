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
	"github.com/tuneinsight/lattigo/v3/bfv"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
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
	// TODO populate session store with own inputs
	return nil
}

func (s *ComputeService) Execute(cd CircuitDesc) error {

	// Idea: full nodes will resolve compute all session and local ciphertext by either resolving the inputs or waiting for them.
	// Light node isolate their inputs and send them to the know full node(s?)/delegates(s?)
	c, exists := s.circuits[cd.ID]
	if !exists {
		return fmt.Errorf("circuit does not exist")
	}

	sess, exists := s.GetSessionFromID(cd.Session)
	if !exists {
		return fmt.Errorf("session does not exist")
	}

	in, out := make(chan pkg.Operand), make(chan pkg.Operand)

	go c.Evaluate(nil, in, out)

	for _, input := range c.Inputs() {
		isLocal := input.NodeID() == s.ID()

		if isLocal {
			ct, exists := sess.Load(input.CiphertextID())
			if !exists {
				return fmt.Errorf("ciphertext %s does not exist locally", input.CiphertextID())
			}
			in <- pkg.Operand{URL: input.URL, Ciphertext: &bfv.Ciphertext{Ciphertext: &ct.Ciphertext}}
			continue
		}

		peer, hasCli := s.peers[input.NodeID()]
		if !hasCli {
			continue
		}

		ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("session_id", "test-session", "node_id", string(s.ID())))
		ctId := input.CiphertextID().ToGRPC()
		resp, err := peer.GetCiphertext(ctx, &api.CiphertextRequest{Id: &ctId})
		if err != nil {
			return err
		}

		ct, err := pkg.NewCiphertextFromGRPC(resp)
		if err != nil {
			return err
		}

		in <- pkg.Operand{URL: input.URL, Ciphertext: &bfv.Ciphertext{Ciphertext: &ct.Ciphertext}}
	}
	close(in)

	for res := range out {
		sess.Store(pkg.Ciphertext{*res.Ciphertext.Ciphertext, pkg.CiphertextMetadata{ID: res.CiphertextID()}})
	}

	return nil
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
