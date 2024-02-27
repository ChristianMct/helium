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
	protocols.Transport

	PutCiphertext(ctx context.Context, ct pkg.Ciphertext) error
	GetCiphertext(ctx context.Context, ctID pkg.CiphertextID) (*pkg.Ciphertext, error)

	// GetAggregationFrom queries the designated node id (typically, the aggregator) for the
	// aggregated share of the designated protocol.
	//GetAggregationOutput(context.Context, protocols.Descriptor) (*protocols.AggregationOutput, error)
}

type Coordinator interface {
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

	CompletedProtocol(protocols.Descriptor) error

	//IncomingAggregationOutput(protocols.AggregationOutput) error

	// // LocalOutput returns a channel where the circuit executing within this context will write its outputs.
	// LocalOutputs() chan pkg.Operand

	// // Execute executes the circuit of the context.
	// Execute(context.Context) error

	// // Get returns the executing circuit operand with the given label.
	GetOperand(context.Context, circuits.OperandLabel) (*circuits.Operand, bool)

	GetFutureOperand(context.Context, circuits.OperandLabel) (*circuits.FutureOperand, bool)

	Wait() error
}

type InputProvider func(context.Context, circuits.OperandLabel) (*rlwe.Plaintext, error)

type OutputReceiver chan<- circuits.Output

var NoInput InputProvider = func(_ context.Context, _ circuits.OperandLabel) (*rlwe.Plaintext, error) { return nil, nil }

var NoOutput OutputReceiver = nil

type Service struct {
	self pkg.NodeID

	sessions pkg.SessionProvider
	*protocols.Executor
	transport Transport

	pubkeyBackend PublicKeyBackend

	inputProvider InputProvider
	localOutputs  chan circuits.Output

	outputsMu sync.RWMutex
	outputs   map[circuits.OperandLabel]*circuits.Operand

	runningCircuitsMu sync.RWMutex
	runningCircuitWg  sync.WaitGroup
	runningCircuits   map[circuits.ID]CircuitInstance

	//running chan struct{}

	// upstream
	coordinator Coordinator

	// downstream coordinator
	incoming, outgoing chan protocols.Event

	// circuit library
	library map[circuits.Name]circuits.Circuit
}

func NewComputeService(ownId pkg.NodeID, sessions pkg.SessionProvider, pkbk PublicKeyBackend, trans Transport) (s *Service, err error) {
	s = new(Service)

	s.self = ownId
	s.sessions = sessions
	s.Executor, err = protocols.NewExectutor(s.self, sessions, s, s.GetProtocolInput, s, trans)
	if err != nil {
		return nil, err
	}
	s.transport = trans
	s.pubkeyBackend = pkbk

	s.runningCircuits = make(map[circuits.ID]CircuitInstance)

	s.incoming = make(chan protocols.Event)
	s.outgoing = make(chan protocols.Event)

	//s.running = make(chan struct{})

	s.localOutputs = make(chan circuits.Output)
	s.outputs = make(map[circuits.OperandLabel]*circuits.Operand)

	return s, nil
}

func (s *Service) Run(ctx context.Context, ip InputProvider, or OutputReceiver, coord Coordinator) error {

	s.coordinator = coord
	s.inputProvider = ip
	go s.Executor.Run(ctx)

	// process incoming upstream Events
	upstreamDone := make(chan struct{})
	go func() {
		for ev := range coord.Incoming() {

			if ev.IsProtocolEvent() {
				pev := *ev.ProtocolEvent

				s.Logf("new coordination event: PROTOCOL %s", pev)

				s.incoming <- pev

				switch pev.EventType {
				case protocols.Completed:
					opls, has := pev.Signature.Args["op"]
					if !has {
						panic("no op argument in circuit protocol event")
					}

					opl := circuits.OperandLabel(opls)
					cid := opl.Circuit()

					s.runningCircuitsMu.RLock()
					c := s.runningCircuits[cid]
					s.runningCircuitsMu.RUnlock()

					c.CompletedProtocol(pev.Descriptor)
					break
				}

				continue
			}

			cev := *ev.CircuitEvent
			s.Logf("new coordination event: CIRCUIT %s", cev)
			switch ev.CircuitEvent.Status {
			case circuits.Executing:
				err := s.runCircuit(ctx, cev.Descriptor)
				if err != nil {
					panic(err)
				}
			case circuits.Completed, circuits.Failed:
				s.runningCircuitsMu.Lock()
				delete(s.runningCircuits, ev.CircuitEvent.ID)
				s.runningCircuitsMu.Unlock()
			}
		}
		close(upstreamDone)
	}()

	//	close(s.running)

	// process incoming downstream coordination events
	downstreamDone := make(chan struct{})
	go func() {
		for pev := range s.outgoing {
			pev := pev
			s.coordinator.Outgoing() <- coordinator.Event{ProtocolEvent: &pev}

			if pev.EventType == protocols.Completed {
				opls, has := pev.Signature.Args["op"]
				if !has {
					panic("no op argument in circuit protocol event")
				}

				opl := circuits.OperandLabel(opls)
				cid := opl.Circuit()

				s.runningCircuitsMu.RLock()
				c, has := s.runningCircuits[cid]
				if !has {
					panic(fmt.Errorf("circuit with id %s is not running", cid))
				}
				s.runningCircuitsMu.RUnlock()

				c.CompletedProtocol(pev.Descriptor)
			}

		}
		close(downstreamDone)
	}()

	// sends the local outputs to the output receiver if any
	go func() {
		if or != nil {
			for lop := range s.localOutputs {
				or <- lop
			}
			close(or)
		} else {
			for range s.localOutputs {
			}
		}
	}()

	<-upstreamDone
	s.Logf("upstream coordinator done")

	s.runningCircuitWg.Wait()
	s.Logf("all circuits done")

	close(s.incoming) // closing downstream coordinator
	<-downstreamDone  // waiting for downstream to close its outgoing channel

	s.Logf("downstream coordinator done, Run returns")
	close(s.coordinator.Outgoing()) // close own outgoing channel
	close(s.localOutputs)
	return nil
}

func (s *Service) runCircuit(ctx context.Context, cd circuits.Descriptor) (err error) {

	c, has := s.library[cd.Name]
	if !has {
		return fmt.Errorf("no registered circuit for name \"%s\"", cd.Name)
	}

	sess, has := s.sessions.GetSessionFromContext(ctx)
	if !has {
		return fmt.Errorf("could not retrieve session from the context")
	}

	params := *sess.Params

	ci, err := circuits.Parse(c, cd, params)
	if err != nil {
		return err
	}

	//<-s.running // waits for the Run function to be called

	if s.isEvaluator(cd, *ci) {
		err = s.runEvaluator(ctx, c, cd, ci, params)
	} else {
		err = s.runParticipant(ctx, c, cd, ci, params)
	}

	return err
}

// TODO: include cd in ci ?
func (s *Service) runEvaluator(ctx context.Context, c circuits.Circuit, cd circuits.Descriptor, ci *circuits.Info, params bgv.Parameters) (err error) {
	s.Logf("started circuit %s as evaluator", cd.ID)

	sessid, _ := pkg.SessionIDFromContext(ctx)

	ev, err := newEvaluator(sessid, c, cd, params, s.pubkeyBackend, s)
	if err != nil {
		return err
	}

	if _, has := s.runningCircuits[cd.ID]; has {
		return fmt.Errorf("circuit with id %s is already runnning", cd.ID)
	}

	s.runningCircuitWg.Add(1)
	s.runningCircuitsMu.Lock()
	s.runningCircuits[cd.ID] = ev
	s.runningCircuitsMu.Unlock()

	s.coordinator.Outgoing() <- coordinator.Event{CircuitEvent: &circuits.Event{Status: circuits.Executing, Descriptor: cd}}

	// evalDone := make(chan struct{})
	go func() {
		err = c(ev)
		if err != nil {
			panic(err)
		}

		err := ev.Wait() // all protocol events have been sent on upstream
		if err != nil {
			panic(err)
		}

		for outLabel := range ci.OutputSet {
			op, has := ev.GetOperand(ctx, outLabel)
			if !has {
				panic(fmt.Errorf("circuit should have output operand %s", outLabel))
			}
			s.outputsMu.Lock()
			s.outputs[outLabel] = op
			s.outputsMu.Unlock()
		}

		for outLabel := range ci.OutputsFor[s.self] {
			fop, has := ev.GetOperand(ctx, outLabel)
			if !has {
				panic(fmt.Errorf("circuit instance has no output label %s", outLabel))
			}
			s.localOutputs <- circuits.Output{ID: cd.ID, Operand: *fop}
		}

		s.coordinator.Outgoing() <- coordinator.Event{CircuitEvent: &circuits.Event{Status: circuits.Completed, Descriptor: cd}}

		s.runningCircuitsMu.Lock()
		delete(s.runningCircuits, cd.ID)
		nRunning := len(s.runningCircuits)
		s.runningCircuitsMu.Unlock()
		s.runningCircuitWg.Done()

		s.Logf("completed circuit %s as evaluator, %d running", cd.ID, nRunning)
		// close(evalDone)
	}()
	return nil
}

func (s *Service) runParticipant(ctx context.Context, c circuits.Circuit, cd circuits.Descriptor, ci *circuits.Info, params bgv.Parameters) error {

	s.Logf("started circuit %s as participant", cd.ID)

	sess, has := s.sessions.GetSessionFromContext(ctx) // put session unwrap earlier
	if !has {
		panic("does not find sess")
	}

	cpk, err := s.pubkeyBackend.GetCollectivePublicKey()
	if err != nil {
		return fmt.Errorf("cannot create encryptor: %w", err)
	}

	part, err := NewParticipant(ctx, cd, ci, sess, s.inputProvider, *cpk, s.transport, s.localOutputs)
	if err != nil {
		return err
	}

	s.runningCircuitWg.Add(1)
	s.runningCircuitsMu.Lock()
	s.runningCircuits[cd.ID] = part
	s.runningCircuitsMu.Unlock()

	go func() {
		err := c(part)
		if err != nil {
			panic(err)
		}
		err = part.Wait()
		if err != nil {
			panic(err)
		}
		s.runningCircuitWg.Done() // TODO: get the circuit complete message in this function to so that all runningcircuit management takes place here
		s.Logf("completed circuit %s as participant", cd.ID)
	}()

	// if s.isInputProvider(cd, *ci) {
	// 	// create encryptor TODO: reuse encryptors
	// 	cpk, err := s.pubkeyBackend.GetCollectivePublicKey()
	// 	if err != nil {
	// 		return fmt.Errorf("cannot create encryptor: %w", err)
	// 	}
	// 	encryptor, err := bgv.NewEncryptor(params, cpk)
	// 	if err != nil {
	// 		return fmt.Errorf("cannot create encryptor: %w", err)
	// 	}

	// 	for inLabel := range ci.InputsFor[s.self] {
	// 		pt, err := s.inputProvider(ctx, inLabel)
	// 		if err != nil {
	// 			return err
	// 		}
	// 		ct, err := encryptor.EncryptNew(pt)
	// 		if err != nil {
	// 			return err
	// 		}
	// 		pkgct := pkg.Ciphertext{CiphertextMetadata: pkg.CiphertextMetadata{ID: pkg.CiphertextID(inLabel)}, Ciphertext: *ct}
	// 		if err = s.transport.PutCiphertext(ctx, pkgct); err != nil { // sends to evaluator
	// 			return err
	// 		}
	// 	}
	// }

	// go func() {
	// 	// TODO wait for COMPLETE ?
	// 	for outLabel := range ci.OutputsFor[s.self] {
	// 		ct, err := s.transport.GetCiphertext(ctx, pkg.CiphertextID(outLabel))
	// 		if err != nil {
	// 			s.Logf("error while retrieving output: %s", err)
	// 		}
	// 		s.localOutputs <- circuits.Output{ID: cd.ID, Operand: circuits.Operand{OperandLabel: outLabel, Ciphertext: &ct.Ciphertext}}
	// 	}
	// 	s.runningCircuitWg.Done()
	// }()

	return nil
}

func (s *Service) RunKeyOperation(ctx context.Context, sig protocols.Signature) (err error) {
	s.Logf("running key operation: %s", sig)
	_, err = s.Executor.RunSignatureAsAggregator(ctx, sig)
	return err
}

func (s *Service) GetCiphertext(ctx context.Context, ctID pkg.CiphertextID) (*pkg.Ciphertext, error) {

	_, exists := s.sessions.GetSessionFromContext(ctx) // TODO per session circuits
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

	var op *circuits.Operand
	var isOutput, isInCircuit bool
	s.outputsMu.RLock()
	op, isOutput = s.outputs[circuits.OperandLabel(ctID)]
	s.outputsMu.RUnlock()
	if !isOutput {
		s.runningCircuitsMu.RLock()
		evalCtx, envExists := s.runningCircuits[cid]
		s.runningCircuitsMu.RUnlock()
		if !envExists {
			return nil, fmt.Errorf("%s is not an output and circuit %s is not running", ctID, ctURL.CircuitID())
		}
		op, isInCircuit = evalCtx.GetOperand(ctx, circuits.OperandLabel(ctURL.String()))
	}

	if !isOutput && !isInCircuit {
		return nil, fmt.Errorf("ciphertext with id %s not found for circuit %s", ctID, ctURL.CircuitID())
	}

	ct = &pkg.Ciphertext{Ciphertext: *op.Ciphertext}
	return ct, nil
}

func (s *Service) PutCiphertext(ctx context.Context, ct pkg.Ciphertext) error {

	_, exists := s.sessions.GetSessionFromContext(ctx) // TODO per-session ciphertexts
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

func (s *Service) RegisterCircuits(cs map[circuits.Name]circuits.Circuit) error {
	for cn, c := range cs {
		if err := s.RegisterCircuit(cn, c); err != nil {
			return err
		}
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

func (s *Service) Put(ctx context.Context, aggOut protocols.AggregationOutput) error {
	c, err := s.getCircuitFromContext(ctx)
	if err != nil {
		return err
	}

	inOpl, has := aggOut.Descriptor.Signature.Args["op"]
	if !has {
		return fmt.Errorf("invalid aggregation output: descriptor does not provide input operand label")
	}

	// inOp, has := c.GetOperand(circuits.OperandLabel(inOpl))
	// if !has {
	// 	return fmt.Errorf("invalid aggregation output: unknown input operand")
	// }

	outOpl := keyOpOutputLabel(circuits.OperandLabel(inOpl), aggOut.Descriptor.Signature)

	fop, has := c.GetFutureOperand(ctx, outOpl)
	if !has {
		return fmt.Errorf("invalid aggregation output: unkown output operand: %s", outOpl)
	}

	out := s.Executor.GetOutput(ctx, aggOut)
	if out.Error != nil {
		return fmt.Errorf("protocol output resulted in an error: %w", err)
	}

	outCt := out.Result.(*rlwe.Ciphertext)

	fop.Set(circuits.Operand{OperandLabel: outOpl, Ciphertext: outCt})

	return nil

}

func (s *Service) Get(ctx context.Context, pd protocols.Descriptor) (*protocols.AggregationOutput, error) {
	return nil, fmt.Errorf("compute service do not enable retrieving aggregation outputs directly")
}

func (s *Service) GetProtocolInput(ctx context.Context, pd protocols.Descriptor) (in protocols.Input, err error) {

	opl, has := pd.Signature.Args["op"]
	if !has {
		return nil, fmt.Errorf("invalid protocol descriptor: no operand specified")
	}

	c, err := s.getCircuitFromOperandLabel(circuits.OperandLabel(opl))
	if err != nil {
		return nil, err
	}

	op, has := c.GetOperand(ctx, circuits.OperandLabel(opl))
	if !has {
		return nil, fmt.Errorf("invalid protocol descriptor: operand label %s not in circuit", opl)
	}

	return op.Ciphertext, nil

}

func (s *Service) Incoming() <-chan protocols.Event {
	return s.incoming
}

func (s *Service) Outgoing() chan<- protocols.Event {
	return s.outgoing
}

func (s *Service) getCircuitFromContext(ctx context.Context) (CircuitInstance, error) {
	cid, has := pkg.CircuitIDFromContext(ctx)
	if !has {
		return nil, fmt.Errorf("should have circuit id in context")
	}

	s.runningCircuitsMu.RLock()
	c, envExists := s.runningCircuits[circuits.ID(cid)]
	s.runningCircuitsMu.RUnlock()
	if !envExists {
		return nil, fmt.Errorf("unknown circuit %s", cid)
	}

	return c, nil
}

func (s *Service) getCircuitFromOperandLabel(opl circuits.OperandLabel) (CircuitInstance, error) {

	cid := opl.Circuit()

	s.runningCircuitsMu.RLock()
	c, envExists := s.runningCircuits[circuits.ID(cid)]
	s.runningCircuitsMu.RUnlock()
	if !envExists {
		return nil, fmt.Errorf("unknown circuit %s", cid)
	}
	return c, nil
}

func (s *Service) isParticipant(cd circuits.Descriptor, ci circuits.Info) bool {
	return s.isInputProvider(cd, ci) || s.isOutputReceiver(cd, ci)
}

func (s *Service) isInputProvider(cd circuits.Descriptor, ci circuits.Info) bool {
	return len(ci.InputsFor[s.self]) > 0
}

func (s *Service) isOutputReceiver(cd circuits.Descriptor, ci circuits.Info) bool {
	return len(ci.OutputsFor[s.self]) > 0
}

func (s *Service) isEvaluator(cd circuits.Descriptor, ci circuits.Info) bool {
	return cd.Evaluator == s.self
}
