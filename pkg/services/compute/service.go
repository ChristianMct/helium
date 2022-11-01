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

	pendingOps map[pkg.OperandLabel]*pkg.FutureOperand

	peers map[pkg.NodeID]api.ComputeServiceClient
}

func NewComputeService(n *node.Node) (s *ComputeService, err error) {
	s = new(ComputeService)
	s.Node = n

	s.circuitsDefs = make(map[string]pkg.LocalCircuitDef)

	s.circuits = make(map[pkg.CircuitID]pkg.Circuit)

	s.pendingOps = make(map[pkg.OperandLabel]*pkg.FutureOperand)

	s.peers = make(map[pkg.NodeID]api.ComputeServiceClient)

	if n.HasAddress() {
		n.RegisterService(&api.ComputeService_ServiceDesc, s)
	}
	return s, nil
}

// Connect creates the grpc connections to the given nodes (represented by their pkg.NodeID's in the map dialers).
// These connections are used to initialise the api.ComputeServiceClient instances of the nodes (stored in peers).
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

func (s *ComputeService) RegisterCircuit(cd pkg.LocalCircuitDef) error {
	if _, exists := s.circuitsDefs[cd.Name]; exists {
		return fmt.Errorf("circuit with name %s already registered", cd.Name)
	}
	s.circuitsDefs[cd.Name] = cd // todo copy
	return nil
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

	c := pkg.NewLocalCircuit(s.circuitsDefs[cd.CircuitName], bfv.NewEvaluator(bfvParams, rlwe.EvaluationKey{Rlk: sess.Rlk}))

	s.circuits[cd.CircuitID] = c

	// adds all local inputs and outputs to pending
	for _, opLabel := range append(c.InputsLabels(), c.OutputsLabels()...) {
		opUrl := pkg.NewURL(string(opLabel))
		if opUrl.Host == string(s.ID()) || len(opUrl.Host) == 0 { // TODO: extract in InputLabel semantic ?
			s.pendingOps[opLabel] = &pkg.FutureOperand{}
		}
	}

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

	lops := make(map[pkg.OperandLabel]pkg.Operand, len(localOps))
	for _, op := range localOps {
		lops[op.OperandLabel] = op
		if fop, isPending := s.pendingOps[op.OperandLabel]; isPending {
			fop.Done(op)
		}
	}

	if s.HasAddress() { // Is full node

		out := make([]pkg.Operand, 0, len(c.OutputsLabels()))
		for _, opLabel := range c.OutputsLabels() {
			opUrl := pkg.NewURL(string(opLabel))
			if opUrl.Host == string(s.ID()) || len(opUrl.Host) == 0 { // TODO: extract in InputLabel semantic ?
				out = append(out, pkg.Operand{OperandLabel: opLabel})
			}
		}

		if len(out) == 0 { // Execute returns if node has no output in the circuit
			log.Printf("Node %s | execute returned\n", s.ID())
			return out, nil
		}

		// query full nodes for inputs
		ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("node_id", string(s.ID()), "session_id", "test-session", "circuit_id", string(cd.CircuitID))) // TODO: assumes a single session named "test-session" :D
		for _, in := range c.InputsLabels() {

			var op pkg.Operand

			if lop, provided := lops[in]; provided {
				op = lop
			} else {
				inUrl := pkg.NewURL(string(in))

				peer, hasCli := s.peers[inUrl.NodeID()]
				if !hasCli {
					continue // TODO should be a better way to check if peer is a light node
				}
				resp, err := peer.GetCiphertext(ctx, &api.CiphertextRequest{Id: inUrl.CiphertextID().ToGRPC()})
				if err != nil {
					log.Printf("Node %s | error while fetching ciphertext %s: %s\n", s.ID(), inUrl, err)
					return nil, err
				}

				var ct *pkg.Ciphertext
				ct, err = pkg.NewCiphertextFromGRPC(resp)
				if err != nil {
					return nil, status.Errorf(codes.InvalidArgument, "invalid ciphertext: %s", err)
				}
				op = pkg.Operand{OperandLabel: in, Ciphertext: &bfv.Ciphertext{Ciphertext: &ct.Ciphertext}}
			}

			c.Inputs() <- op
		}

		log.Printf("Node %s | evaluating circuit %s, waiting on input %v \n", s.ID(), cd.CircuitID, c.InputsLabels())
		err := c.Evaluate()
		if err != nil {
			return nil, err
		}

		// gather the results
		for op := range c.Outputs() {
			for i := range out {
				if op.OperandLabel == out[i].OperandLabel {
					out[i].Ciphertext = op.Ciphertext
				}
			}
		}

		// checks if all expected outputs have been received
		for _, opOut := range out {
			if opOut.Ciphertext == nil {
				err = fmt.Errorf("circuit closed its output channel but did not output %s", opOut.OperandLabel)
			}
		}

		log.Printf("Node %s | execute returned\n", s.ID())
		return out, err
	} else { // Is light node
		for _, inLabel := range c.InputsLabels() {

			in := pkg.NewURL(string(inLabel))

			if in.Host != string(s.ID()) {
				//log.Printf("Node %s | has no inputs %s for circuit %s\n", s.ID(), in.Host, cid)
				continue
			}

			log.Printf("Node %s | sending inputs for circuit %s\n", s.ID(), cd.CircuitID)

			op, provided := lops[pkg.OperandLabel(in.CiphertextBaseID())]
			if !provided {
				log.Printf("Node %s | input %s was not provided", s.ID(), in.String())
				return nil, fmt.Errorf("input %s was not provided", in.String())
			}

			ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("node_id", string(s.ID()), "session_id", "test-session", "circuit_id", string(cd.CircuitID))) // TODO: assumes a single session named "test-session" :D

			ct := pkg.Ciphertext{Ciphertext: *op.Ciphertext.Ciphertext, CiphertextMetadata: pkg.CiphertextMetadata{ID: pkg.CiphertextID(op.OperandLabel)}}

			for peerId, peer := range s.peers {
				_, err := peer.PutCiphertext(ctx, ct.ToGRPC())
				if err != nil {
					log.Printf("Node %s | error while sending input %s\n", s.ID(), err)
				} else {
					log.Printf("Node %s | sent input %s to %s\n", s.ID(), pkg.CiphertextID(op.OperandLabel), peerId)
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

	var ct pkg.Ciphertext
	// first, check if ct is part of a circuit
	if fop, isPending := s.pendingOps[pkg.OperandLabel(id)]; isPending {
		log.Printf("Node %s | got pending request from %s - GET %s \n", s.ID(), ictx.SenderID(), id)
		op := <-fop.Await()
		ct = pkg.Ciphertext{Ciphertext: *op.Ciphertext.Ciphertext}
	} else if ct, exists = sess.Load(id); !exists {
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
		op := pkg.Operand{OperandLabel: pkg.OperandLabel(url.String()), Ciphertext: &bfv.Ciphertext{Ciphertext: &ct.Ciphertext}}
		if c.Expects(op) {
			c.Inputs() <- op
		} else {
			return nil, status.Errorf(codes.InvalidArgument, "unexpected ciphertext %s, expects %v", op.OperandLabel, c.Expected())
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
