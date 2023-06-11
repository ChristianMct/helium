package compute

import (
	"context"
	"fmt"
	"log"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/protocols"
	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/ldsec/helium/pkg/transport"
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
	id pkg.NodeID

	*api.UnimplementedComputeServiceServer

	sessions  pkg.SessionProvider
	transport transport.ComputeServiceTransport

	evalEnvs map[pkg.CircuitID]ServiceEvaluationEnvironment
}

func NewComputeService(id pkg.NodeID, sessions pkg.SessionProvider, trans transport.ComputeServiceTransport) (s *Service, err error) {
	s = new(Service)

	s.id = id

	s.sessions = sessions
	s.transport = trans

	s.evalEnvs = make(map[pkg.CircuitID]ServiceEvaluationEnvironment)

	return s, nil
}

func RegisterCircuit(name string, cd Circuit) error {
	if _, exists := CircuitDefs[name]; exists {
		return fmt.Errorf("circuit with name %s already registered", name)
	}
	CircuitDefs[name] = cd
	return nil
}

// LoadCircuit loads the circuit creating the necessary evaluation environments.
// This method should be called before the cloud goes online.
func (s *Service) LoadCircuit(ctx context.Context, cd Signature, label pkg.CircuitID) error {

	if _, exist := s.evalEnvs[label]; exist {
		return fmt.Errorf("circuit with label %s already exists", label)
	}

	sess, exist := s.sessions.GetSessionFromContext(ctx)
	if !exist {
		return fmt.Errorf("session does not exist")
	}

	cDef, exist := CircuitDefs[cd.CircuitName]
	if !exist {
		return fmt.Errorf("circuit definition with name \"%s\" does not exist", cd.CircuitName)
	}

	if cd.Delegate == "" || cd.Delegate == s.ID() {
		s.evalEnvs[label] = s.newFullEvaluationContext(sess, label, cDef, nil)
	} else {
		s.evalEnvs[label] = s.newDelegatedEvaluatorContext(cd.Delegate, sess, label, cDef)
	}

	return nil
}

// TODO: async execute that returns ops as they are computed
func (s *Service) Execute(ctx context.Context, label pkg.CircuitID, localOps ...pkg.Operand) ([]pkg.Operand, error) {

	log.Printf("%s | started execute with args %v \n", s.ID(), localOps)

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

	outset := c.CircuitDescription().OutputsFor[s.id]
	out := make([]pkg.Operand, 0, len(outset))
	for opLabel := range outset {
		out = append(out, pkg.Operand{OperandLabel: opLabel})
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

	log.Printf("%s | execute returned\n", s.ID())
	return out, err
}

func (s *Service) SendCiphertext(ctx context.Context, to pkg.NodeID, ct pkg.Ciphertext) error {
	return s.transport.PutCiphertext(ctx, to, ct)
}

func (s *Service) GetCiphertext(ctx context.Context, ctID pkg.CiphertextID) (*pkg.Ciphertext, error) {

	sess, exists := s.sessions.GetSessionFromIncomingContext(ctx)
	if !exists {
		return nil, status.Errorf(codes.InvalidArgument, "invalid session id")
	}

	ctURL, err := pkg.ParseURL(string(ctID))
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext id format")
	}

	if ctURL.NodeID() != "" && ctURL.NodeID() != s.id {
		return nil, fmt.Errorf("non-local ciphertext id")
	}

	var ct *pkg.Ciphertext

	if ctURL.CircuitID() != "" { // ctid belongs to a circuit
		evalCtx, envExists := s.evalEnvs[ctURL.CircuitID()]
		if !envExists {
			return nil, fmt.Errorf("ciphertext with id %s not found for circuit %s", ctID, ctURL.CircuitID())
		}
		op := evalCtx.Get(pkg.OperandLabel(ctURL.String()))
		ct = &pkg.Ciphertext{Ciphertext: *op.Ciphertext}
	} else if ct, exists = sess.CiphertextStore.Load(ctID); !exists {
		return nil, fmt.Errorf("ciphertext with id %s not found in session", ctID)
	}

	return ct, nil
}

// func (s *Service) GetCiphertext(ctx context.Context, ctr *api.CiphertextRequest) (*api.Ciphertext, error) {

// 	ctMsg := ct.ToGRPC()

// 	log.Printf("%s | got request from %s - GET %s \n", s.ID(), pkg.SenderIDFromIncomingContext(ctx), id)

// 	return ctMsg, nil
// }

func (s *Service) PutCiphertext(ctx context.Context, ct pkg.Ciphertext) error {

	sess, exists := s.sessions.GetSessionFromIncomingContext(ctx)
	if !exists {
		return fmt.Errorf("invalid session id")
	}

	ctURL, err := pkg.ParseURL(string(ct.ID))
	if err != nil {
		return fmt.Errorf("invalid ciphertext id \"%s\": %w", ct.ID, err)
	}

	// checks if input is sent for a circuit
	cid := ctURL.CircuitID()
	if cid != "" {

		c, envExists := s.evalEnvs[cid]
		if !envExists {
			return fmt.Errorf("for unknown circuit %s", cid)
		}

		op := pkg.Operand{OperandLabel: pkg.OperandLabel(ct.ID), Ciphertext: &ct.Ciphertext}
		err = c.IncomingInput(op)
		if err != nil {
			return err
		}

		log.Printf("%s | got new ciphertext %s for circuit id \"%s\" \n", s.ID(), ct.ID, cid)
	} else {

		// stores the ciphertext
		err = sess.CiphertextStore.Store(ct)
		if err != nil {
			return err
		}

		log.Printf("%s | got ciphertext %s for session storage\n", s.ID(), ct.ID)
	}
	return nil

	// // checks if input is sent for a circuit
	// cid := pkg.CircuitIDFromIncomingContext(ctx)
	// if cid != "" {

	// 	c, envExists := s.evalEnvs[cid]
	// 	if !envExists {
	// 		return nil, status.Errorf(codes.InvalidArgument, "circuit %s does not exist", cid)
	// 	}

	// 	cFull, isFull := c.(*fullEvaluatorContext)
	// 	if !isFull {
	// 		return nil, status.Errorf(codes.InvalidArgument, "circuit %s not executing as full context", cid)
	// 	}

	// 	op := pkg.Operand{OperandLabel: pkg.OperandLabel(ct.ID), Ciphertext: &ct.Ciphertext}

	// 	cFull.inputs <- op

	// 	log.Printf("%s | got request from %s - PUT %s for circuit id \"%s\" \n", s.ID(), pkg.SenderIDFromIncomingContext(ctx), ct.ID, cid)
	// 	return ct.ID.ToGRPC(), nil
	// }

	// // otherwise just store the ct in the session
	// if ct.ID == "" {
	// 	ct.ID = pkg.CiphertextID(uuid.New().String())
	// }

	// // stores the ciphertext
	// err = sess.Store(ct)
	// if err != nil {
	// 	return nil, status.Errorf(codes.Internal, fmt.Sprintf("%s", err))
	// }

	// log.Printf("%s | got request from %s - PUT %s for session storage\n", s.ID(), pkg.SenderIDFromIncomingContext(ctx), ct.ID)
	// return &api.CiphertextID{CiphertextId: string(ct.ID)}, nil
}

func (s *Service) ID() pkg.NodeID {
	return s.id
}

type ProtocolEnvironment struct { // TODO dedup with Setup
	incoming <-chan protocols.Share
	outgoing chan<- protocols.Share
}

func (pe *ProtocolEnvironment) OutgoingShares() chan<- protocols.Share {
	return pe.outgoing
}

func (pe *ProtocolEnvironment) IncomingShares() <-chan protocols.Share {
	return pe.incoming
}
