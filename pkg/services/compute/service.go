package compute

import (
	"context"
	"fmt"
	"log"

	"github.com/google/uuid"
	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/node"
	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/tuneinsight/lattigo/v3/bfv"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type ComputeService struct {
	*node.Node
	*api.UnimplementedComputeServiceServer

	circuitsDefs map[string]pkg.LocalCircuitDef
	circuits     map[pkg.CircuitID]pkg.Circuit

	peers map[pkg.NodeID]api.ComputeServiceClient
}

func NewComputeService(n *node.Node) (s *ComputeService, err error) {
	s = new(ComputeService)
	s.Node = n

	s.circuitsDefs = make(map[string]pkg.LocalCircuitDef)
	s.circuitsDefs["ComponentWiseProduct4P"] = pkg.ComponentWiseProduct4P

	s.circuits = make(map[pkg.CircuitID]pkg.Circuit)

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
	CircuitName string
	CircuitID   pkg.CircuitID
	SessionID   pkg.SessionID
}

func (s *ComputeService) LoadCircuit(cd CircuitDesc) error {

	if _, exist := s.circuits[cd.CircuitID]; exist {
		return fmt.Errorf("circuit with id %s already exists", cd.CircuitID)
	}

	if _, exist := s.circuitsDefs[cd.CircuitName]; !exist {
		return fmt.Errorf("circuit definition with name \"%s\" does not already exists", cd.CircuitName)
	}

	sess, exist := s.GetSessionFromID(cd.SessionID)
	if !exist {
		return fmt.Errorf("session with id %s does not exist", cd.SessionID)
	}

	bfvParams, _ := bfv.NewParameters(*sess.Params, 65537)

	s.circuits[cd.CircuitID] = pkg.NewLocalCircuit(s.circuitsDefs[cd.CircuitName], bfv.NewEvaluator(bfvParams, rlwe.EvaluationKey{Rlk: sess.Rlk}))

	return nil
}

// TODO: async execute that returns ops as they are computed
// TODO: generic execute that executes all circuits ?
func (s *ComputeService) Execute(cd CircuitDesc, localOps ...pkg.Operand) ([]pkg.Operand, error) {

	// Idea: full nodes will resolve compute all session and local ciphertext by either resolving the inputs or waiting for them.
	// Light node isolate their inputs and send them to the know full node(s?)/delegates(s?)
	// TODO: decouple ciphertext store and PUT/GET from session, there should be a Circuit-level entity that manage them
	// after LoadCircuit, each node knows what circuit needs what input and knows how to respond to queries (potentially by blocking)

	c, exists := s.circuits[cd.CircuitID]
	if !exists {
		return nil, fmt.Errorf("circuit does not exist")
	}

	lops := make(map[pkg.URL]pkg.Operand, len(localOps))
	for _, op := range localOps {
		lops[*op.URL] = op
	}

	if s.HasAddress() { // Is full node
		log.Printf("Node %s | evaluating circuit %s, waiting on input %v \n", s.ID(), cd.CircuitID, c.Expected())
		err := c.Evaluate()
		if err != nil {
			return nil, err
		}
		out := make([]pkg.Operand, 0, len(c.OutputsLabels()))
		for op := range c.OutputsChannel() {
			out = append(out, op)
		}
		log.Printf("Node %s | execute returned\n", s.ID())
		return out, nil
	} else { // Is light node
		for cid, c := range s.circuits {
			cid := cid
			c := c
			for _, in := range c.InputsLabels() {

				if in.Host != string(s.ID()) {
					//log.Printf("Node %s | has no inputs %s for circuit %s\n", s.ID(), in.Host, cid)
					continue
				}

				log.Printf("Node %s | sending inputs for circuit %s\n", s.ID(), cid)

				op, provided := lops[*pkg.NewURL(string(in.CiphertextBaseID()))]
				if !provided {
					log.Printf("Node %s | input %s was not provided", s.ID(), in.String())
					return nil, fmt.Errorf("input %s was not provided", in.String())
				}

				ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("node_id", string(s.ID()), "session_id", "test-session", "circuit_id", string(cid))) // TODO: assumes a single session named "test-session" :D

				ct := pkg.Ciphertext{Ciphertext: *op.Ciphertext.Ciphertext, CiphertextMetadata: pkg.CiphertextMetadata{ID: op.CiphertextBaseID()}}

				for peerId, peer := range s.peers {
					_, err := peer.PutCiphertext(ctx, ct.ToGRPC())
					if err != nil {
						log.Printf("Node %s | error while sending input %s\n", s.ID(), err)
					} else {
						log.Printf("Node %s | sent input %s to %s\n", s.ID(), op.CiphertextBaseID(), peerId)
					}
				}
			}

		}
	}

	log.Printf("Node %s | execute returned\n", s.ID())
	return nil, nil
}

func (s *ComputeService) GetCiphertext(ctx context.Context, ctr *api.CiphertextRequest) (*api.Ciphertext, error) {

	ictx := pkg.Context{Context: ctx}
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

	return ctMsg, nil
}

func (s *ComputeService) PutCiphertext(ctx context.Context, apict *api.Ciphertext) (ctId *api.CiphertextID, err error) {
	ictx := pkg.Context{Context: ctx}
	sess, exists := s.GetSessionFromID(ictx.SessionID())
	if !exists {
		return nil, status.Errorf(codes.InvalidArgument, "invalid session id")
	}

	var ct *pkg.Ciphertext
	ct, err = pkg.NewCiphertextFromGRPC(apict)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid ciphertext: %s", err)
	}

	log.Printf("Node %s | got request from %s - PUT %s \n", s.ID(), ictx.SenderID(), ct.ID)

	// checks if input is sent for a circuit
	cid := ictx.CircuitID()
	if cid != "" {

		c, exists := s.circuits[cid]
		if !exists {
			return nil, status.Errorf(codes.InvalidArgument, "circuit %s does not exist", cid)
		}

		url := new(pkg.URL)
		url.Host = ictx.SenderID()
		url.Path = "/" + string(ct.ID)
		op := pkg.Operand{URL: url, Ciphertext: &bfv.Ciphertext{Ciphertext: &ct.Ciphertext}}
		if c.Expects(op) {
			c.InputsChannel() <- op
		} else {
			return nil, status.Errorf(codes.InvalidArgument, "unexpected ciphertext %s, expects %v", op, c.Expected())
		}

		return ct.ID.ToGRPC(), nil
	}

	// otherwise just store the ct in the session
	if ct.ID == "" {
		ct.ID = pkg.CiphertextID(uuid.New().String())
	}

	// stores the ciphertext
	err = sess.Store(*ct)
	if err != nil {
		return nil, status.Errorf(codes.Internal, fmt.Sprintf("%s", err))
	}

	return &api.CiphertextID{CiphertextId: string(ct.ID)}, nil
}
