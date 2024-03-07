package compute

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/ldsec/helium/pkg/circuits"
	"github.com/ldsec/helium/pkg/coordinator"
	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/protocols"
	"github.com/tuneinsight/lattigo/v4/bgv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"golang.org/x/sync/errgroup"
)

type Transport interface {
	protocols.Transport

	PutCiphertext(ctx context.Context, ct pkg.Ciphertext) error
	GetCiphertext(ctx context.Context, ctID pkg.CiphertextID) (*pkg.Ciphertext, error)
}

type Coordinator interface {
	Incoming() <-chan coordinator.Event
	Outgoing() chan<- coordinator.Event
}

type PublicKeyBackend interface {
	GetCollectivePublicKey(context.Context) (*rlwe.PublicKey, error)
	GetGaloisKey(ctx context.Context, galEl uint64) (*rlwe.GaloisKey, error)
	GetRelinearizationKey(context.Context) (*rlwe.RelinearizationKey, error)
}

type OperandBackend interface {
	Set(circuits.Operand) error
	Get(circuits.OperandLabel) (*circuits.Operand, error)
}

type FHEProvider interface {
	GetEncoder(ctx context.Context) (*bgv.Encoder, error)
	GetEncryptor(ctx context.Context) (*rlwe.Encryptor, error)
	GetEvaluator(ctx context.Context, rlk bool, galEls []uint64) (*fheEvaluator, error)
	GetDecryptor(ctx context.Context) (*rlwe.Decryptor, error)
}

// CircuitInstance defines the interface that is available to the service
// to access evaluation contexts of a particular circuit evaluation.
type CircuitInstance interface {
	Init(ctx context.Context, ci circuits.Info) (err error)

	Eval(ctx context.Context, c circuits.Circuit) (err error)

	IncomingOperand(circuits.Operand) error

	CompletedProtocol(protocols.Descriptor) error

	// // Get returns the executing circuit operand with the given label.
	GetOperand(context.Context, circuits.OperandLabel) (*circuits.Operand, bool)

	GetFutureOperand(context.Context, circuits.OperandLabel) (*circuits.FutureOperand, bool)

	Wait() error
}

type InputProvider func(context.Context, circuits.OperandLabel) (any, error)

type OutputReceiver chan<- circuits.Output

var NoInput InputProvider = func(_ context.Context, _ circuits.OperandLabel) (any, error) { return nil, nil }

var NoOutput OutputReceiver = nil

type Service struct {
	config ServiceConfig
	self   pkg.NodeID

	sessions pkg.SessionProvider
	*protocols.Executor
	transport Transport

	pubkeyBackend PublicKeyBackend

	inputProvider InputProvider
	localOutputs  chan circuits.Output

	outputsMu sync.RWMutex
	outputs   map[circuits.OperandLabel]*circuits.Operand

	queuedCircuits chan circuits.Descriptor

	runningCircuitsMu sync.RWMutex
	//runningCircuitWg  sync.WaitGroup
	runningCircuits map[circuits.ID]CircuitInstance

	completedCircuits chan circuits.Descriptor
	//running chan struct{}

	// upstream coordinator
	coordinator Coordinator

	// downstream coordinator
	incoming, outgoing chan protocols.Event

	// circuit library
	library map[circuits.Name]circuits.Circuit
}

const (
	DefaultCircQueueSize        = 100
	DefaultMaxCircuitEvaluation = 10
)

type ServiceConfig struct {
	CircQueueSize        int
	MaxCircuitEvaluation int
	Protocols            protocols.ExecutorConfig
}

func NewComputeService(ownId pkg.NodeID, sessions pkg.SessionProvider, conf ServiceConfig, pkbk PublicKeyBackend, trans Transport) (s *Service, err error) {
	s = new(Service)

	s.config = conf
	if s.config.CircQueueSize == 0 {
		s.config.CircQueueSize = DefaultCircQueueSize
	}
	if s.config.MaxCircuitEvaluation == 0 {
		s.config.MaxCircuitEvaluation = DefaultMaxCircuitEvaluation
	}

	s.self = ownId
	s.sessions = sessions
	s.Executor, err = protocols.NewExectutor(conf.Protocols, s.self, sessions, s, s.GetProtocolInput, trans)
	if err != nil {
		return nil, err
	}
	s.transport = trans
	s.pubkeyBackend = pkg.NewCachedPublicKeyBackend(pkbk)

	s.queuedCircuits = make(chan circuits.Descriptor, conf.CircQueueSize)

	s.runningCircuits = make(map[circuits.ID]CircuitInstance)

	// coordinator
	s.incoming = make(chan protocols.Event)
	s.outgoing = make(chan protocols.Event)

	//s.running = make(chan struct{})

	s.localOutputs = make(chan circuits.Output)
	s.outputs = make(map[circuits.OperandLabel]*circuits.Operand)

	return s, nil
}

func (s *Service) Init(ctx context.Context, complCd, runCd []circuits.Descriptor, complPd, runPd []protocols.Descriptor) error {

	// stacks the completed circuit in a queue for processing by Run
	s.completedCircuits = make(chan circuits.Descriptor, len(complCd))
	for _, ccd := range complCd {
		s.completedCircuits <- ccd
	}

	// create and queues the running circuits
	for _, rcd := range runCd {
		if err := s.createCircuit(ctx, rcd); err != nil {
			return err
		}
		s.queuedCircuits <- rcd
	}

	// sends the completed
	for _, cpd := range complPd {

		if !cpd.Signature.Type.IsCompute() {
			continue
		}

		if err := s.sendCompletedPdToCircuit(cpd); err != nil {
			return err
		}
	}

	// sends the running pd to the protocol executor
	for _, rpd := range runPd {
		if !rpd.Signature.Type.IsCompute() {
			continue
		}
		s.incoming <- protocols.Event{EventType: protocols.Started, Descriptor: rpd}
	}

	return nil
}

func (s *Service) Run(ctx context.Context, ip InputProvider, or OutputReceiver, coord Coordinator) error {

	s.coordinator = coord
	s.inputProvider = ip
	go func() {
		if err := s.Executor.Run(ctx); err != nil {
			panic(err) // TODO: return in Run
		}
	}()

	// process incoming upstream Events
	go func() {
		for ev := range coord.Incoming() {

			if ev.IsProtocolEvent() {
				pev := *ev.ProtocolEvent

				s.Logf("new coordination event: PROTOCOL %s", pev)

				s.incoming <- pev

				switch pev.EventType {
				case protocols.Completed:
					if err := s.sendCompletedPdToCircuit(pev.Descriptor); err != nil {
						panic(err)
					}
				}

				continue
			}

			cev := *ev.CircuitEvent
			s.Logf("new coordination event: CIRCUIT %s", cev)
			switch ev.CircuitEvent.Status {
			case circuits.Started:
				err := s.createCircuit(ctx, cev.Descriptor)
				if err != nil {
					panic(err)
				}
				s.queuedCircuits <- cev.Descriptor
			case circuits.Completed, circuits.Failed:
				s.runningCircuitsMu.Lock()
				delete(s.runningCircuits, ev.CircuitEvent.ID)
				s.runningCircuitsMu.Unlock()
			}
		}
		s.Logf("upstream coordinator done")
		close(s.queuedCircuits)
	}()

	//	close(s.running)

	// process downstream incoming coordination events
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

	// process the circuit execution queue
	evalRoutines, erctx := errgroup.WithContext(ctx)
	for i := 0; i < s.config.MaxCircuitEvaluation; i++ {
		evalRoutines.Go(func() error {
			for cd := range s.queuedCircuits {
				if err := s.runCircuit(erctx, cd); err != nil {
					return err
				}
			}
			return nil
		})
	}

	// fetches the output for completed circuits (light nodes only)
	go func() {
		if or != nil {
			for cd := range s.completedCircuits {
				c, has := s.library[cd.Name]
				if !has {
					panic(fmt.Errorf("no registered circuit for name \"%s\"", cd.Name))
				}

				sess, has := s.sessions.GetSessionFromContext(ctx)
				if !has {
					panic(fmt.Errorf("could not retrieve session from the context"))
				}

				params := *sess.Params

				cinf, err := circuits.Parse(c, cd, params)
				if err != nil {
					panic(err)
				}

				for opl := range cinf.OutputsFor[s.self] {
					ct, err := s.transport.GetCiphertext(ctx, pkg.CiphertextID(opl))
					if err != nil {
						panic(err)
					}

					or <- circuits.Output{ID: cd.ID, Operand: circuits.Operand{OperandLabel: opl, Ciphertext: &ct.Ciphertext}}
				}
			}
		} else {
			for range s.completedCircuits {
			}
		}
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

	err := evalRoutines.Wait()
	if err != nil {
		return err
	}
	s.Logf("all circuits done")

	close(s.incoming) // closing downstream coordinator
	<-downstreamDone  // waiting for downstream to close its outgoing channel

	s.Logf("downstream coordinator done, Run returns")
	close(s.coordinator.Outgoing()) // close own outgoing channel
	close(s.localOutputs)
	return nil
}

func (s *Service) sendCompletedPdToCircuit(pd protocols.Descriptor) error {
	opls, has := pd.Signature.Args["op"]
	if !has {
		panic("no op argument in circuit protocol event")
	}

	opl := circuits.OperandLabel(opls)
	cid := opl.Circuit()

	s.runningCircuitsMu.RLock()
	c, has := s.runningCircuits[cid]
	s.runningCircuitsMu.RUnlock()
	if !has {
		panic(fmt.Errorf("circuit is not runnig: %s", cid))
	}

	return c.CompletedProtocol(pd)
}

// validateCircuitDescriptor checks that a circuit descriptor is valid and can be executed by
// the service.
func (s *Service) validateCircuitDescriptor(cd circuits.Descriptor) error {
	if len(cd.ID) == 0 {
		return fmt.Errorf("circuit descriptor has no id")
	}
	if len(cd.Name) == 0 {
		return fmt.Errorf("circuit descriptor has no name")
	}
	if len(cd.NodeMapping) == 0 {
		return fmt.Errorf("circuit descriptor has no node mapping")
	}
	if len(cd.Evaluator) == 0 {
		return fmt.Errorf("circuit descriptor has no evaluator")
	}
	// TODO: further checks
	return nil
}

func (s *Service) createCircuit(ctx context.Context, cd circuits.Descriptor) (err error) {
	var ci CircuitInstance
	sess, has := s.sessions.GetSessionFromContext(ctx) // put session unwrap earlier
	if !has {
		return fmt.Errorf("session not found from context")
	}

	if err := s.validateCircuitDescriptor(cd); err != nil {
		return fmt.Errorf("invalid circuit descriptor: %w", err)
	}

	if s.isEvaluator(cd) {
		ci = &evaluator{
			ctx:         ctx,
			cDesc:       cd,
			sess:        sess,
			protoExec:   s,
			fheProvider: s,
		}
	} else {
		ci = &participant{
			ctx:           ctx,
			cd:            cd,
			sess:          sess,
			inputProvider: s.inputProvider,
			or:            s.localOutputs,
			trans:         s.transport,
			fheProvider:   s,
			incpd:         make(chan protocols.Descriptor, 100), // TODO: not ideal
		}

	}
	s.runningCircuitsMu.Lock()
	_, has = s.runningCircuits[cd.ID]
	if has {
		s.runningCircuitsMu.Unlock()
		return fmt.Errorf("circuit with id %s is already runnning", cd.ID)
	}
	s.runningCircuits[cd.ID] = ci
	s.runningCircuitsMu.Unlock()

	s.Logf("created circuit %s", cd.ID)
	return
}

func (s *Service) runCircuit(ctx context.Context, cd circuits.Descriptor) (err error) {

	s.runningCircuitsMu.RLock()
	cinst, has := s.runningCircuits[cd.ID]
	s.runningCircuitsMu.RUnlock()
	if !has {
		return fmt.Errorf("circuit %s was not created", cd.ID)
	}

	c, has := s.library[cd.Name]
	if !has {
		return fmt.Errorf("no registered circuit for name \"%s\"", cd.Name)
	}

	sess, has := s.sessions.GetSessionFromContext(ctx)
	if !has {
		return fmt.Errorf("could not retrieve session from the context")
	}

	params := *sess.Params

	cinf, err := circuits.Parse(c, cd, params)
	if err != nil {
		return err
	}

	err = cinst.Init(ctx, *cinf)
	if err != nil {
		return fmt.Errorf("error at circuit initialization: %w", err)
	}
	//<-s.running // waits for the Run function to be called

	if s.isEvaluator(cd) {
		err = s.runCircuitAsEvaluator(ctx, c, cinst, cd, cinf)
	} else {
		err = s.runCircuitAsParticipant(ctx, c, cinst, cd)
	}

	return err
}

// TODO: include cd in ci ?
func (s *Service) runCircuitAsEvaluator(ctx context.Context, c circuits.Circuit, ev CircuitInstance, cd circuits.Descriptor, ci *circuits.Info) (err error) {
	s.Logf("started circuit %s as evaluator", cd.ID)

	s.coordinator.Outgoing() <- coordinator.Event{CircuitEvent: &circuits.Event{Status: circuits.Started, Descriptor: cd}}

	err = ev.Eval(ctx, c)
	if err != nil {
		return fmt.Errorf("error at circuit evaluation: %w", err)
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
	//s.runningCircuitWg.Done()

	s.Logf("completed circuit %s as evaluator, %d running", cd.ID, nRunning)
	// close(evalDone)
	//}()
	return nil
}

func (s *Service) runCircuitAsParticipant(ctx context.Context, c circuits.Circuit, part CircuitInstance, cd circuits.Descriptor) error {

	s.Logf("started circuit %s as participant", cd.ID)

	err := part.Eval(ctx, c)
	if err != nil {
		return err
	}

	//s.runningCircuitWg.Done() // TODO: get the circuit complete message in this function to so that all runningcircuit management takes place here
	s.Logf("completed circuit %s as participant", cd.ID)

	return nil
}

func (s *Service) RunKeyOperation(ctx context.Context, sig protocols.Signature) (err error) {
	s.Logf("running key operation: %s", sig)
	err = s.Executor.RunSignature(ctx, sig, s.Put)
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
		sessid, _ := pkg.SessionIDFromContext(ctx)
		return fmt.Errorf("invalid session id \"%s\"", sessid)
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

	s.Logf("recieved ciphertext for operand %s", op.OperandLabel)

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

// protocols.Coordinator interface
func (s *Service) Incoming() <-chan protocols.Event {
	return s.incoming
}

func (s *Service) Outgoing() chan<- protocols.Event {
	return s.outgoing
}

// FHEProvider interface
func (s *Service) GetEncoder(ctx context.Context) (*bgv.Encoder, error) {
	sess, has := s.sessions.GetSessionFromContext(ctx)
	if !has {
		return nil, fmt.Errorf("no session found for this context")
	}

	return bgv.NewEncoder(*sess.Params), nil
}

func (s *Service) GetEncryptor(ctx context.Context) (*rlwe.Encryptor, error) {

	sess, has := s.sessions.GetSessionFromContext(ctx)
	if !has {
		return nil, fmt.Errorf("no session found for this context")
	}

	cpk, err := s.pubkeyBackend.GetCollectivePublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot retrieve the collective public key : %w", err)
	}

	return rlwe.NewEncryptor(sess.Params, cpk)
}

func (s *Service) GetEvaluator(ctx context.Context, relin bool, galEls []uint64) (*fheEvaluator, error) {
	sess, has := s.sessions.GetSessionFromContext(ctx)
	if !has {
		return nil, fmt.Errorf("no session found for this context")
	}

	return newLattigoEvaluator(ctx, relin, galEls, *sess.Params, s.pubkeyBackend)
}

func (s *Service) GetDecryptor(ctx context.Context) (*rlwe.Decryptor, error) {
	sess, has := s.sessions.GetSessionFromContext(ctx)
	if !has {
		return nil, fmt.Errorf("no session found for this context")
	}

	return rlwe.NewDecryptor(sess.Params, rlwe.NewSecretKey(sess.Params)) // decryptor under sk=0 (sk is determined at output)

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

func (s *Service) isEvaluator(cd circuits.Descriptor) bool {
	return cd.Evaluator == s.self
}

func (s *Service) Logf(msg string, v ...any) {
	log.Printf("%s | [compute] %s\n", s.self, fmt.Sprintf(msg, v...))
}
