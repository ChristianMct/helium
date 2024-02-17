package compute

import (
	"context"
	"fmt"
	"sync"

	"github.com/ldsec/helium/pkg/circuits"
	"github.com/ldsec/helium/pkg/coordinator"
	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/protocols"
	"github.com/tuneinsight/lattigo/v4/bgv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

type Transport interface {
	OperandBackend
	// GetAggregationFrom queries the designated node id (typically, the aggregator) for the
	// aggregated share of the designated protocol.
	GetAggregationOutput(context.Context, protocols.Descriptor) (*protocols.AggregationOutput, error)
}

type Coordinator interface {
	GetProtocolDescriptor(ctx context.Context, sig protocols.Signature) (*protocols.Descriptor, error)
	Incoming() <-chan coordinator.Event
	Outgoing() chan<- coordinator.Event
}

type PublicKeyBackend interface {
	GetCollectivePublicKey() (*rlwe.PublicKey, error)
	GetGaloisKey(galEl uint64) (*rlwe.GaloisKey, error)
	GetRelinearizationKey() (*rlwe.RelinearizationKey, error)
}

type OperandBackend interface {
	Set(circuits.Operand) error
	Get(circuits.OperandLabel) (*circuits.Operand, error)
}

// CircuitInstance defines the interface that is available to the service
// to access evaluation contexts of a particular circuit evaluation.
type CircuitInstance interface {

	// // CircuitDescription returns the CircuitDescription for the circuit executing within this context.
	// CircuitDescription() CircuitDescription

	// // LocalInput provides the local inputs to the circuit executing within this context.
	// LocalInputs([]pkg.Operand) error

	IncomingOperand(circuits.Operand) error

	// // LocalOutput returns a channel where the circuit executing within this context will write its outputs.
	// LocalOutputs() chan pkg.Operand

	// // Execute executes the circuit of the context.
	// Execute(context.Context) error

	// // Get returns the executing circuit operand with the given label.
	GetOperand(circuits.OperandLabel) (*circuits.Operand, error)
}

type InputProvider func(context.Context, circuits.OperandLabel) (*rlwe.Plaintext, error)

var NoInput InputProvider = func(_ context.Context, _ circuits.OperandLabel) (*rlwe.Plaintext, error) { return nil, nil }

type Service struct {
	self pkg.NodeID

	sessions pkg.SessionProvider
	*protocols.Executor
	transport   Transport
	coordinator Coordinator

	pubkeyBackend PublicKeyBackend

	ctBackend OperandBackend

	inputProvider InputProvider

	runningCircuitsMu sync.RWMutex
	runningCircuits   map[circuits.ID]CircuitInstance

	// circuit library
	library map[circuits.Name]circuits.Circuit
}

func NewComputeService(ownId pkg.NodeID, sessions pkg.SessionProvider, pkbk PublicKeyBackend, executor *protocols.Executor, trans Transport) (s *Service, err error) {
	s = new(Service)

	s.self = ownId
	s.sessions = sessions
	s.Executor = executor
	s.transport = trans
	s.pubkeyBackend = pkbk

	return s, nil
}

func (s *Service) Run(ctx context.Context, coord Coordinator) {

	s.coordinator = coord

}

func (s *Service) RunCircuit(ctx context.Context, cd circuits.Descriptor) (chan circuits.Operand, error) {

	c, has := s.library[cd.Name]
	if !has {
		return nil, fmt.Errorf("no registered circuit for name \"%s\"", cd.Name)
	}

	if s.self != cd.Evaluator && !cd.InputPartiesIDSet().Contains(s.self) {
		return nil, fmt.Errorf("node has no role in the circuit")
	}

	sess, has := s.sessions.GetSessionFromContext(ctx)
	if !has {
		return nil, fmt.Errorf("could not retrieve session from the context")
	}

	params := *sess.Params

	if s.self == cd.Evaluator {
		s.runEvaluator(ctx, c, cd, params)
	}

	out, err := s.runParticipant(ctx, c, cd, params)
	if err != nil {
		return nil, err
	}

	return out, err
}

func (s *Service) runEvaluator(ctx context.Context, c circuits.Circuit, cd circuits.Descriptor, params bgv.Parameters) error {
	ev, err := newEvaluator(c, cd, params, s.pubkeyBackend, s)
	if err != nil {
		return err
	}

	if _, has := s.runningCircuits[cd.ID]; has {
		return fmt.Errorf("circuit with id %s is already runnning", cd.ID)
	}

	s.runningCircuitsMu.Lock()
	s.runningCircuits[cd.ID] = ev
	s.runningCircuitsMu.Unlock()

	// TODO notify coordinator

	err = c(ev)
	if err != nil {
		return err
	}

	s.runningCircuitsMu.Lock()
	delete(s.runningCircuits, cd.ID)
	s.runningCircuitsMu.Unlock()

	return nil
}

func (s *Service) runParticipant(ctx context.Context, c circuits.Circuit, cd circuits.Descriptor, params bgv.Parameters) (chan circuits.Operand, error) {

	ci, err := circuits.Parse(c, cd, params)
	if err != nil {
		return nil, err
	}

	// create encryptor TODO: reuse encryptors
	cpk, err := s.pubkeyBackend.GetCollectivePublicKey()
	if err != nil {
		return nil, fmt.Errorf("cannot create encryptor: %w", err)
	}
	encryptor, err := bgv.NewEncryptor(params, cpk)
	if err != nil {
		return nil, fmt.Errorf("cannot create encryptor: %w", err)
	}

	for inLabel := range ci.InputsFor[s.self] {
		pt, err := s.inputProvider(ctx, inLabel)
		if err != nil {
			return nil, err
		}
		ct, err := encryptor.EncryptNew(pt)
		if err != nil {
			return nil, err
		}
		op := circuits.Operand{OperandLabel: inLabel, Ciphertext: ct}
		if err = s.transport.Set(op); err != nil { // sends to evaluator
			return nil, err
		}
	}

	outs := make(chan circuits.Operand, len(ci.OutputsFor[s.self]))
	go func() {
		// TODO wait for COMPLETE ?
		for outLabel := range ci.OutputsFor[s.self] {
			op, err := s.transport.Get(outLabel)
			if err != nil {
				s.Logf("error while retrieving output: %s", err)
			}
			outs <- *op
		}
	}()

	return outs, nil
}

func (s *Service) RunKeyOperation(ctx context.Context, sig protocols.Signature, input circuits.Operand, output *circuits.FutureOperand) (err error) {
	pd, err := s.coordinator.GetProtocolDescriptor(ctx, sig)
	if err != nil {
		return err
	}
	aggOut, err := s.Executor.RunProtocol(ctx, *pd, input)
	if err != nil {
		return err
	}
	out := s.Executor.GetOutput(ctx, *pd, <-aggOut, input)
	if out.Error != nil {
		return err
	}
	ct := out.Result.(*rlwe.Ciphertext)
	op := circuits.Operand{Ciphertext: ct}
	output.Set(op)
	return nil
}

func (s *Service) GetCiphertext(ctx context.Context, ctID pkg.CiphertextID) (*pkg.Ciphertext, error) {

	_, exists := s.sessions.GetSessionFromIncomingContext(ctx) // TODO per session circuits
	if !exists {
		return nil, fmt.Errorf("invalid session id")
	}

	//s.Logf("%s queried for ciphertext id %s", pkg.SenderIDFromIncomingContext(ctx), ctID)

	ctURL, err := pkg.ParseURL(string(ctID))
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext id format")
	}

	if ctURL.NodeID() != "" && ctURL.NodeID() != s.self {
		return nil, fmt.Errorf("non-local ciphertext id")
	}

	cid := circuits.ID(ctURL.CircuitID())
	if len(cid) == 0 {
		return nil, fmt.Errorf("ciphertext label does not include a circuit ID")
	}

	var ct *pkg.Ciphertext

	s.runningCircuitsMu.RLock()
	evalCtx, envExists := s.runningCircuits[cid]
	s.runningCircuitsMu.RUnlock()
	if !envExists {
		return nil, fmt.Errorf("ciphertext with id %s not found for circuit %s", ctID, ctURL.CircuitID())
	}
	op, err := evalCtx.GetOperand(circuits.OperandLabel(ctURL.String()))
	ct = &pkg.Ciphertext{Ciphertext: *op.Ciphertext}
	return ct, nil
}

func (s *Service) PutCiphertext(ctx context.Context, ct pkg.Ciphertext) error {

	_, exists := s.sessions.GetSessionFromIncomingContext(ctx) // TODO per-session ciphertexts
	if !exists {
		return fmt.Errorf("invalid session id")
	}

	ctURL, err := pkg.ParseURL(string(ct.ID))
	if err != nil {
		return fmt.Errorf("invalid ciphertext id \"%s\": %w", ct.ID, err)
	}

	cid := circuits.ID(ctURL.CircuitID())

	if len(cid) == 0 {
		return fmt.Errorf("ciphertext label does not include a circuit ID")
	}

	s.runningCircuitsMu.RLock()
	c, envExists := s.runningCircuits[cid]
	s.runningCircuitsMu.RUnlock()
	if !envExists {
		return fmt.Errorf("for unknown circuit %s", cid)
	}

	op := circuits.Operand{OperandLabel: circuits.OperandLabel(ct.ID), Ciphertext: &ct.Ciphertext}
	err = c.IncomingOperand(op)
	if err != nil {
		return err
	}

	return nil
}

func (s *Service) RegisterCircuit(name circuits.Name, circ circuits.Circuit) error {
	if s.library == nil {
		s.library = make(map[circuits.Name]circuits.Circuit)
	}
	if _, has := s.library[name]; has {
		return fmt.Errorf("circuit name \"%s\" already registered", name)
	}
	s.library[name] = circ
	return nil
}
