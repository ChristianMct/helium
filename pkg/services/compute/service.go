package compute

import (
	"context"
	"fmt"
	"log"
	"path"
	"strings"

	"github.com/google/uuid"
	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/node"
	"github.com/ldsec/helium/pkg/services"
	pkg "github.com/ldsec/helium/pkg/session"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var CircuitDefs = map[string]Circuit{}

type Signature struct {
	CircuitName   string
	CircuitParams map[string]interface{}
	Delegate      pkg.NodeID
}

type Service struct {
	*node.Node
	*services.Environment
	*api.UnimplementedComputeServiceServer

	evalEnvs map[pkg.CircuitID]ServiceEvaluationEnvironment

	peers map[pkg.NodeID]api.ComputeServiceClient
}

func NewComputeService(n *node.Node) (s *Service, err error) {
	s = new(Service)
	s.Node = n

	s.Environment, err = services.NewEnvironment(n.ID())
	if err != nil {
		return nil, err
	}
	s.evalEnvs = make(map[pkg.CircuitID]ServiceEvaluationEnvironment)

	s.peers = make(map[pkg.NodeID]api.ComputeServiceClient)

	if n.IsFullNode() {
		n.RegisterService(&api.ComputeService_ServiceDesc, s)
	}

	return s, nil
}

// Connect creates the grpc connections to the given nodes (represented by their pkg.NodeID's in the map dialers).
// These connections are used to initialise the api.ComputeServiceClient instances of the nodes (stored in peers).
func (s *Service) Connect() {
	for peerID, peerConn := range s.Conns() {
		s.peers[peerID] = api.NewComputeServiceClient(peerConn)
	}
}

func RegisterCircuit(name string, cd Circuit) error {
	if _, exists := CircuitDefs[name]; exists {
		return fmt.Errorf("circuit with name %s already registered", name)
	}
	CircuitDefs[name] = cd
	return nil
}

func (s *Service) LoadCircuit(ctx context.Context, cd Signature, label pkg.CircuitID) error {

	if _, exist := s.evalEnvs[label]; exist {
		return fmt.Errorf("circuit with label %s already exists", label)
	}

	sess, exist := s.GetSessionFromContext(ctx)
	if !exist {
		return fmt.Errorf("session does not exist")
	}

	cDef, exist := CircuitDefs[cd.CircuitName]
	if !exist {
		return fmt.Errorf("circuit definition with name \"%s\" does not exist", cd.CircuitName)
	}

	if cd.Delegate == "" || cd.Delegate == s.ID() {
		s.evalEnvs[label] = s.newFullEvaluationContext(sess, s.peers, label, cDef, nil)
	} else {
		s.evalEnvs[label] = s.newDelegatedEvaluatorContext(cd.Delegate, s.peers[cd.Delegate], sess, label, cDef)
	}

	return nil
}

// TODO: async execute that returns ops as they are computed
func (s *Service) Execute(ctx context.Context, label pkg.CircuitID, localOps ...pkg.Operand) ([]pkg.Operand, error) {

	log.Printf("Node %s | started execute with args %v \n", s.ID(), localOps)

	c, exists := s.evalEnvs[label]
	if !exists {
		return nil, fmt.Errorf("circuit does not exist")
	}

	ctx = pkg.AppendCircuitID(ctx, label)

	err := c.LocalInputs(localOps)
	if err != nil {
		return nil, err
	}

	// starts the evaluation routine
	go func() {
		if errExec := c.Execute(ctx); errExec != nil {
			panic(errExec)
		}
	}()

	out := make([]pkg.Operand, 0, len(c.CircuitDescription().OutputSet))
	for opLabel := range c.CircuitDescription().OutputSet {
		opURL := NewURL(string(opLabel))
		if opURL.Host == string(s.ID()) || len(opURL.Host) == 0 { // TODO: extract in InputLabel semantic ?
			out = append(out, pkg.Operand{OperandLabel: opLabel})
		}
	}

	// gather the results
	for op := range c.LocalOutputs() {
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
}

func (s *Service) GetCiphertext(ctx context.Context, ctr *api.CiphertextRequest) (*api.Ciphertext, error) {

	sess, exists := s.GetSessionFromIncomingContext(ctx)
	if !exists {
		return nil, status.Errorf(codes.InvalidArgument, "invalid session id")
	}

	id := pkg.CiphertextID(ctr.Id.CiphertextId)

	var ct pkg.Ciphertext

	ctURL, err := ParseURL(ctr.Id.CiphertextId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid ciphertext id")
	}
	if dir, _ := path.Split(ctURL.Path); len(dir) > 0 { // ctid belongs to a circuit
		root := strings.SplitN(strings.Trim(dir, "/"), "/", 2)[0]
		evalCtx, envExists := s.evalEnvs[pkg.CircuitID(root)]
		if !envExists {
			log.Printf("Node %s | got request from %s - GET %s: circuit not found \"%s\" \n", s.ID(), pkg.SenderIDFromIncomingContext(ctx), id, root)
			return nil, status.Errorf(codes.NotFound, "circuit not found")
		}
		op := evalCtx.Get(pkg.OperandLabel(id))
		ct = pkg.Ciphertext{Ciphertext: *op.Ciphertext}
	} else if ct, exists = sess.Load(id); !exists {
		return nil, status.Errorf(codes.NotFound, "ciphertext not found")
	}

	ctMsg := ct.ToGRPC()

	log.Printf("Node %s | got request from %s - GET %s \n", s.ID(), pkg.SenderIDFromIncomingContext(ctx), id)

	return ctMsg, nil
}

func (s *Service) PutCiphertext(ctx context.Context, apict *api.Ciphertext) (ctID *api.CiphertextID, err error) {

	sess, exists := s.GetSessionFromIncomingContext(ctx)
	if !exists {
		return nil, status.Errorf(codes.InvalidArgument, "invalid session id")
	}

	var ct *pkg.Ciphertext
	ct, err = pkg.NewCiphertextFromGRPC(apict)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid ciphertext: %s", err)
	}

	// checks if input is sent for a circuit
	cid := pkg.CircuitIDFromIncomingContext(ctx)
	if cid != "" {

		c, envExists := s.evalEnvs[cid]
		if !envExists {
			return nil, status.Errorf(codes.InvalidArgument, "circuit %s does not exist", cid)
		}

		cFull, isFull := c.(*fullEvaluatorContext)
		if !isFull {
			return nil, status.Errorf(codes.InvalidArgument, "circuit %s not executing as full context", cid)
		}

		op := pkg.Operand{OperandLabel: pkg.OperandLabel(ct.ID), Ciphertext: &ct.Ciphertext}

		cFull.inputs <- op

		log.Printf("Node %s | got request from %s - PUT %s for circuit id \"%s\" \n", s.ID(), pkg.SenderIDFromIncomingContext(ctx), ct.ID, cid)
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

	log.Printf("Node %s | got request from %s - PUT %s for session storage\n", s.ID(), pkg.SenderIDFromIncomingContext(ctx), ct.ID)
	return &api.CiphertextID{CiphertextId: string(ct.ID)}, nil
}

func (s *Service) GetShare(ctx context.Context, req *api.ShareRequest) (*api.Share, error) {
	return s.Environment.GetShare(ctx, req)
}

func (s *Service) PutShare(ctx context.Context, share *api.Share) (*api.Void, error) {
	return s.Environment.PutShare(ctx, share)
}
