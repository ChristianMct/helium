package compute

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/circuits"
	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/protocols"
	"github.com/ldsec/helium/pkg/transport"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v4/drlwe"
	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe/ringqp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var CircuitDefsLock sync.RWMutex
var CircuitDefs = map[string]Circuit{}

const parallelExecutions int = 10

type Service struct {
	id pkg.NodeID

	evaluatorID pkg.NodeID // TODO per circuit ?

	*api.UnimplementedComputeServiceServer

	sessions  pkg.SessionProvider
	transport transport.ComputeServiceTransport
	pkBackend PublicKeyBackend

	peers *pkg.PartySet

	runningCircuitsMu sync.RWMutex
	circuits          map[pkg.CircuitID]CircuitInstance

	// TODO Extract ProtocolRunner
	runningProtosMu sync.RWMutex
	runningProtos   map[pkg.ProtocolID]struct {
		pd       protocols.Descriptor
		incoming chan protocols.Share
	}

	incomingPdescMu sync.RWMutex
	incomingPdesc   map[string]chan protocols.Descriptor
}

func NewComputeService(id, evaluatorID pkg.NodeID, sessions pkg.SessionProvider, trans transport.ComputeServiceTransport, pkBackend PublicKeyBackend) (s *Service, err error) {
	s = new(Service)

	s.id = id

	s.evaluatorID = evaluatorID

	s.sessions = sessions
	s.transport = trans

	s.pkBackend = NewCachedPublicKeyBackend(pkBackend)

	s.peers = pkg.NewPartySet()

	s.circuits = make(map[pkg.CircuitID]CircuitInstance)

	// TODO extract protocolrunner
	s.runningProtos = make(map[pkg.ProtocolID]struct {
		pd       protocols.Descriptor
		incoming chan protocols.Share
	})

	s.incomingPdesc = make(map[string]chan protocols.Descriptor)

	go func() {
		for share := range s.transport.IncomingShares() {
			s.runningProtosMu.RLock()
			proto, exists := s.runningProtos[share.ProtocolID]
			s.runningProtosMu.RUnlock()
			if !exists {
				panic(fmt.Errorf("protocol %s is not running", share.ProtocolID))
			}
			proto.incoming <- share
		}
	}()

	return s, nil
}

func RegisterCircuit(name string, cd Circuit) error {
	CircuitDefsLock.Lock()
	defer CircuitDefsLock.Unlock()
	if _, exists := CircuitDefs[name]; exists {
		return fmt.Errorf("circuit with name %s already registered", name)
	}
	CircuitDefs[name] = cd
	return nil
}

func CircuitDefinition(label string) (c Circuit, exists bool) {
	CircuitDefsLock.RLock()
	defer CircuitDefsLock.RUnlock()
	c, exists = CircuitDefs[label]
	return
}

// LoadCircuit loads the circuit creating the necessary evaluation environments.
// This method should be called before the cloud goes online.
func (s *Service) LoadCircuit(ctx context.Context, sig circuits.Signature) (CircuitInstance, error) {

	cid := sig.CircuitID

	s.runningCircuitsMu.RLock()
	if _, exist := s.circuits[cid]; exist {
		return nil, fmt.Errorf("circuit with label %s already exists", cid)
	}
	s.runningCircuitsMu.RUnlock()

	sess, exist := s.sessions.GetSessionFromContext(ctx)
	if !exist {
		return nil, fmt.Errorf("session does not exist")
	}

	cDef, exist := CircuitDefinition(sig.CircuitName)
	if !exist {
		return nil, fmt.Errorf("circuit definition with name \"%s\" does not exist", sig.CircuitName)
	}

	var ci CircuitInstance
	if s.IsEvaluator() {
		ci = s.newFullEvaluationContext(sess, s.pkBackend, cid, cDef, nil)
	} else {
		ci = s.newDelegatedEvaluatorContext(s.evaluatorID, sess, cid, cDef)
	}

	s.runningCircuitsMu.Lock()
	s.circuits[cid] = ci
	s.runningCircuitsMu.Unlock()

	return ci, nil
}

type CircuitOutput struct {
	pkg.OperandLabel
	Pt    *rlwe.Plaintext
	Error error
}

func (s *Service) IsEvaluator() bool {
	return s.id == s.evaluatorID
}

func (s *Service) RunKeySwitch(ctx context.Context, sig protocols.Signature, in pkg.Operand) (outOp pkg.Operand, err error) {
	sess, has := s.sessions.GetSessionFromContext(ctx)
	if !has {
		return pkg.Operand{}, fmt.Errorf("no such session")
	}

	protoDesc := protocols.Descriptor{Signature: sig}
	protoDesc.Aggregator = s.evaluatorID

	switch {
	case len(protoDesc.Participants) > 0:

	// CASE T < N
	case len(protoDesc.Participants) == 0 && sess.T < len(sess.Nodes):
		partSet := utils.NewEmptySet[pkg.NodeID]()
		if sess.Contains(s.id) {
			partSet.Add(s.id)
		}

		if sess.Contains(pkg.NodeID(sig.Args["target"])) {
			partSet.Add(pkg.NodeID(sig.Args["target"]))
		}

		// Wait for enough parties to connect
		online, err := s.peers.WaitForRegisteredIDSet(context.Background(), sess.T-len(partSet))
		if err != nil {
			panic(err)
		}

		// randomizes the remaining participants among the set of registered peers
		online.Remove(partSet.Elements()...)
		partSet.AddAll(utils.GetRandomSetOfSize(sess.T-len(partSet), online))

		protoDesc.Participants = partSet.Elements()
		//pd.Participants = pkg.GetRandomClientSlice(sess.T, sess.Nodes) // Fault injection

	// CASE N
	default:
		protoDesc.Participants = make([]pkg.NodeID, len(sess.Nodes))
		copy(protoDesc.Participants, sess.Nodes)
	}

	ksInt, err := protocols.NewKeyswitchProtocol(protoDesc, sess)
	if err != nil {
		panic(err)
	}

	pid := ksInt.ID()

	s.runningProtosMu.Lock()
	_, exists := s.runningProtos[pid]
	if exists {
		s.runningProtosMu.Unlock()
		panic(fmt.Errorf("protocol already running: %s", pid))
	}
	incShares := make(chan protocols.Share)
	s.runningProtos[pid] = struct {
		pd       protocols.Descriptor
		incoming chan protocols.Share
	}{ksInt.Desc(), incShares}
	s.runningProtosMu.Unlock()

	ksInt.Input(in.Ciphertext)

	s.transport.PutCircuitUpdates(circuits.Update{
		Signature: circuits.Signature{}, // TODO
		Status:    circuits.Running,
		StatusUpdate: &protocols.StatusUpdate{
			Descriptor: protoDesc,
			Status:     protocols.Running,
		}})

	s.Logf("started executing %s", sig)
	agg := <-ksInt.Aggregate(context.Background(), &ProtocolEnvironment{incoming: incShares, outgoing: nil})
	if agg.Error != nil {
		return pkg.Operand{}, agg.Error
	}

	s.runningProtosMu.Lock()
	close(s.runningProtos[pid].incoming)
	delete(s.runningProtos, pid)
	s.runningProtosMu.Unlock()

	s.transport.PutCircuitUpdates(circuits.Update{
		Signature: circuits.Signature{}, // TODO
		Status:    circuits.Running,
		StatusUpdate: &protocols.StatusUpdate{
			Descriptor: protoDesc,
			Status:     protocols.OK,
		}})

	outCt := (<-ksInt.Output(agg)).Result.(*rlwe.Ciphertext)
	target := pkg.NodeID(protoDesc.Signature.Args["target"])
	if protoDesc.Signature.Type == protocols.DEC && sess.T < len(sess.Nodes) && sess.Contains(target) {

		lagrangeCoeff := s.getLagrangeCoeff(sess, target, protoDesc.Participants)
		ringQP := &ringqp.Ring{RingQ: sess.Params.RingQ()}
		// If decrypt among T<N, pre-multiplies the c1 elem by the Lagrange coeff.
		// This avoids requiring participant set on the receiver party side for decryption.
		ringQP.MulRNSScalarMontgomery(ringqp.Poly{Q: outCt.Value[1]}, lagrangeCoeff, ringqp.Poly{Q: outCt.Value[1]})
	}
	outOp = pkg.Operand{Ciphertext: outCt}
	outOp.OperandLabel = pkg.OperandLabel(fmt.Sprintf("%s-%s-out", in.OperandLabel, sig.Type))
	return outOp, nil
}

func (s *Service) GetProtoDescAndRunKeySwitch(ctx context.Context, sig protocols.Signature, in pkg.Operand) (out pkg.Operand, err error) {

	sess, has := s.sessions.GetSessionFromContext(ctx)
	if !has {
		return pkg.Operand{}, fmt.Errorf("no such session")
	}

	s.incomingPdescMu.Lock()
	pdc, has := s.incomingPdesc[sig.String()]
	if !has {
		pdc = make(chan protocols.Descriptor)
		s.incomingPdesc[sig.String()] = pdc
	}
	s.incomingPdescMu.Unlock()

	s.Logf("waiting for protocol description for %s", sig)
	pd := <-pdc

	p, err := protocols.NewProtocol(pd, sess)
	if err != nil {
		return pkg.Operand{}, err
	}
	cks, _ := p.(protocols.KeySwitchInstance)

	cks.Input(in.Ciphertext)

	s.Logf("started executing %s", sig)
	cks.Aggregate(context.Background(), &ProtocolEnvironment{outgoing: s.transport.OutgoingShares()})

	out.OperandLabel = pkg.OperandLabel(fmt.Sprintf("%s-%s-out", in.OperandLabel, sig.Type))
	return out, nil
}

type InputProvider func(context.Context, pkg.OperandLabel) (*rlwe.Plaintext, error)

var NoInput InputProvider = func(_ context.Context, _ pkg.OperandLabel) (*rlwe.Plaintext, error) { return nil, nil }

// TODO: async execute that returns ops as they are computed
// func (s *Service) Execute(ctx context.Context, label pkg.CircuitID, localOps ...pkg.Operand) ([]pkg.Operand, error) {
func (s *Service) Execute(ctx context.Context, sigs chan circuits.Signature, ip InputProvider, outs chan CircuitOutput) error {

	sess, has := s.sessions.GetSessionFromContext(ctx)
	if !has {
		return fmt.Errorf("no session found in context")
	}

	log.Printf("%s | started compute execute\n", s.ID())

	if !s.IsEvaluator() {
		if sigs != nil {
			s.Logf("client submission of Signatures not supported yet, discarding sigs...")
		}

		sigs = make(chan circuits.Signature)
		outCtx := pkg.GetOutgoingContext(ctx, s.id)
		cus, err := s.transport.RegisterForComputeAt(outCtx, s.evaluatorID)
		if err != nil {
			return err
		}
		go func() {
			for cu := range cus {
				if cu.StatusUpdate == nil { // TODO cleaner status/actions + closing channels
					sigs <- cu.Signature
					s.Logf("new circuit update: created %s", cu.Signature)
				} else {
					if cu.StatusUpdate.Status == protocols.OK {
						s.Logf("new circuit update: got status OK for %s", cu.StatusUpdate.Signature)
						continue
					}
					s.incomingPdescMu.Lock()
					pdc, has := s.incomingPdesc[cu.StatusUpdate.Signature.String()]
					if !has {
						pdc = make(chan protocols.Descriptor, 1)
						s.incomingPdesc[cu.StatusUpdate.Signature.String()] = pdc
					}
					s.incomingPdescMu.Unlock()
					pdc <- cu.StatusUpdate.Descriptor
					s.Logf("new circuit update: got protocol descriptor for %s", cu.StatusUpdate.Signature)
				}

			}
			close(sigs)
		}()
	}

	// initializes an encryptor for the inputs. TODO: check if node actually needs it.
	var cpk *rlwe.PublicKey
	var encryptor *rlwe.Encryptor
	var err error
	cpk, err = s.pkBackend.GetCollectivePublicKey()
	if err != nil {
		return fmt.Errorf("error while loading encryption context: %w", err)
	}

	encryptor, err = rlwe.NewEncryptor(sess.Params, cpk)
	if err != nil {
		return fmt.Errorf("error while loading encryption context: %w", err)
	}

	var sk *rlwe.SecretKey
	var decryptor *rlwe.Decryptor
	if sess.Contains(s.id) {
		sk, err = sess.GetSecretKey()
		if err != nil {
			return err
		}
		if sess.T < len(sess.Nodes) {
			tsk, err := sess.GetThresholdSecretKey()
			if err != nil {
				return err
			}
			sk = &rlwe.SecretKey{Value: tsk.Poly}
		}
	}

	wg := new(sync.WaitGroup)
	for w := 0; w < parallelExecutions; w++ {
		wg.Add(1)
		w := w
		go func() {
			defer wg.Done()

			encryptor := encryptor.ShallowCopy()
			if sk != nil { // TODO: use ShallowCopy when fixed on lattigo side
				decryptor, err = rlwe.NewDecryptor(sess.Params, sk)
				if err != nil {
					panic(err)
				}
			}

			for sig := range sigs {

				sig := sig
				cid := sig.CircuitID
				ctx = pkg.AppendCircuitID(ctx, cid)

				s.Logf("processing signature %s on goroutine %d", sig, w)

				c, err := s.LoadCircuit(ctx, sig)
				if err != nil {
					panic(fmt.Errorf("could not load circuit: %w", err))
				}

				if s.IsEvaluator() {
					s.transport.PutCircuitUpdates(circuits.Update{Signature: sig, Status: circuits.Running})
				}

				// extracts own input labels TODO: put in circuitDesc ?
				localInputsLabels := make(utils.Set[pkg.OperandLabel])
				for lbl := range c.CircuitDescription().InputSet {
					if lbl.HasHost(s.id) {
						localInputsLabels.Add(lbl)
					}
				}

				localOps := []pkg.Operand{}
				for lbl := range localInputsLabels {
					inPt, err := ip(ctx, lbl)
					if err != nil {
						panic(fmt.Errorf("input provider returned an error: %w", err))
					}
					ct, err := encryptor.EncryptNew(inPt)
					if err != nil {
						panic(fmt.Errorf("could not encrypt input plaintext: %w", err))
					}
					localOps = append(localOps, pkg.Operand{OperandLabel: lbl, Ciphertext: ct})
				}

				err = c.LocalInputs(localOps)
				if err != nil {
					panic(fmt.Errorf("bad input to circuit: %w", err))
				}

				// starts the evaluation routine
				go func() {
					if errExec := c.Execute(ctx); errExec != nil {
						panic(errExec)
					}
				}()

				for op := range c.LocalOutputs() {
					if len(c.CircuitDescription().OutputsFor[s.id]) > 0 {
						if sess.Contains(s.id) {
							s.Logf("decrypting output operand %s", op.OperandLabel)
							ptdec := decryptor.DecryptNew(op.Ciphertext)
							outs <- CircuitOutput{OperandLabel: op.OperandLabel, Pt: ptdec, Error: nil}
						} else {
							s.Logf("got output operand %s", op.OperandLabel)
							pt := &rlwe.Plaintext{Operand: op.Operand, Value: op.Operand.Value[0]}
							outs <- CircuitOutput{OperandLabel: op.OperandLabel, Pt: pt, Error: nil}
						}

					}
				}
			}
		}()
	}

	wg.Wait()

	close(outs)

	s.transport.Close()

	log.Printf("%s | execute returned\n", s.ID())
	return nil
}

func (s *Service) SendCiphertext(ctx context.Context, to pkg.NodeID, ct pkg.Ciphertext) error {
	return s.transport.PutCiphertext(ctx, to, ct)
}

func (s *Service) GetCiphertext(ctx context.Context, ctID pkg.CiphertextID) (*pkg.Ciphertext, error) {

	sess, exists := s.sessions.GetSessionFromIncomingContext(ctx)
	if !exists {
		return nil, status.Errorf(codes.InvalidArgument, "invalid session id")
	}

	s.Logf("%s queried for ciphertext id %s", pkg.SenderIDFromIncomingContext(ctx), ctID)

	ctURL, err := pkg.ParseURL(string(ctID))
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext id format")
	}

	if ctURL.NodeID() != "" && ctURL.NodeID() != s.id {
		return nil, fmt.Errorf("non-local ciphertext id")
	}

	var ct *pkg.Ciphertext

	if ctURL.CircuitID() != "" { // ctid belongs to a circuit
		s.runningCircuitsMu.RLock()
		evalCtx, envExists := s.circuits[ctURL.CircuitID()]
		s.runningCircuitsMu.RUnlock()
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
		s.runningCircuitsMu.RLock()
		c, envExists := s.circuits[cid]
		s.runningCircuitsMu.RUnlock()
		if !envExists {
			return fmt.Errorf("for unknown circuit %s", cid)
		}

		op := pkg.Operand{OperandLabel: pkg.OperandLabel(ct.ID), Ciphertext: &ct.Ciphertext}
		err = c.IncomingOperand(op)
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
}

func (s *Service) ID() pkg.NodeID {
	return s.id
}

func (s *Service) SetPublicKeyBackend(pkbk PublicKeyBackend) { // TODO: provided at init
	s.pkBackend = pkbk
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

// Register is called by the transport when a new peer register itself for the setup.
func (s *Service) Register(peer pkg.NodeID) error {
	if err := s.peers.Register(peer); err != nil {
		s.Logf("error when registering peer %s for compute: %s", peer, err)
		return err
	}
	s.Logf("compute registered peer %v", peer)
	return nil // TODO: Implement
}

// Unregister is called by the transport when a peer is unregistered from the setup.
func (s *Service) Unregister(peer pkg.NodeID) error {
	if err := s.peers.Unregister(peer); err != nil {
		s.Logf("error when unregistering peer %s for compute: %s", peer, err)
		return err
	}
	s.Logf("compute unregistered peer %v", peer)
	return nil // TODO: Implement
}

func (s *Service) Logf(msg string, v ...any) {
	log.Printf("%s | %s\n", s.id, fmt.Sprintf(msg, v...))
}

// getLagrangeCoeff computes the Lagrange coefficient for party target in the sk reconstruction from T<N shares by
// the participant group.
// TODO: replace by some Lattigo interface ?
func (s *Service) getLagrangeCoeff(sess *pkg.Session, target pkg.NodeID, participants []pkg.NodeID) ring.RNSScalar {

	own := sess.SPKS[target]
	if own == 0 {
		panic(fmt.Errorf("bad target: %s is not in %v", target, sess.SPKS))
	}

	others := make([]drlwe.ShamirPublicPoint, 0)
	for _, p := range participants {
		if p != target {
			others = append(others, sess.SPKS[p])
		}
	}

	ringQP := &ringqp.Ring{RingQ: sess.Params.RingQ()}
	lagrangeCoeff := ringQP.NewRNSScalarFromUInt64(1)

	for i, s := range ringQP.RingQ.SubRings {
		lagrangeCoeff[i] = ring.MForm(lagrangeCoeff[i], s.Modulus, s.BRedConstant)
	}

	// precomputes lagrange coefficient factors
	//lagrangeCoeffs := make(map[drlwe.ShamirPublicPoint]ring.RNSScalar)
	for _, spk := range others {
		if spk != own {
			tmp1 := ringQP.NewRNSScalar()
			ringQP.SubRNSScalar(ringQP.NewRNSScalarFromUInt64(uint64(spk)), ringQP.NewRNSScalarFromUInt64(uint64(own)), tmp1)
			ringQP.Inverse(tmp1)
			ringQP.MulRNSScalar(tmp1, ringQP.NewRNSScalarFromUInt64(uint64(spk)), tmp1)
			ringQP.MulRNSScalar(lagrangeCoeff, tmp1, lagrangeCoeff)
		}
	}
	return lagrangeCoeff
}
