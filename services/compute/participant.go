package compute

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"slices"

	"golang.org/x/exp/maps"

	"github.com/ChristianMct/helium/circuits"
	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/sessions"
	"github.com/ChristianMct/helium/utils"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he"
	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
	"github.com/tuneinsight/lattigo/v5/schemes/ckks"
	"github.com/tuneinsight/lattigo/v5/utils/bignum"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"
)

// participantRuntime is a runtime for a participant (a non-evaluator node) in a computation.
// It implements the CircuitRuntime (for the service side) and the EvaluationContext (for the circuit code) interfaces.
// This implementation:
//   - only resolves this node's input, by calling the user-proved InputProvider, then it encrypts and sends them to the evaluator,
//   - only performs symbolic execution of the circuit
//   - participates to key operation protocols by querying the evaluator for input operands, and track the protocols' completion.
//   - resolves outputs by querying them from the evaluator.
//
// The participantRuntime is a stateful object that is created and used for a single evaluation of a single circuit.
// It performs automatic translation of operand labels from the circuit definition to the running instance.
type participantRuntime struct {

	// inst
	ctx           context.Context // TODO: check if storing this context this way is a problem
	cd            circuits.Descriptor
	sess          *sessions.Session
	inputProvider InputProvider
	trans         Transport
	or            OutputReceiver
	fheProvider   FHEProvider
	incpd         chan protocols.Descriptor // buffer for pd incoming before Init

	// init
	*protocols.CompleteMap
	Encoder
	*rlwe.Encryptor
	*rlwe.Decryptor

	// data
	inputs map[circuits.OperandLabel]*utils.Future[circuits.Input]
}

// Service interface

func (p *participantRuntime) Init(ctx context.Context, md circuits.Metadata, nid sessions.NodeID) (err error) {

	p.Encoder, err = p.fheProvider.GetEncoder(ctx)
	if err != nil {
		return err
	}

	p.Encryptor, err = p.fheProvider.GetEncryptor(ctx)
	if err != nil {
		return err
	}

	p.Decryptor, err = p.fheProvider.GetDecryptor(ctx)
	if err != nil {
		return err
	}

	p.CompleteMap = protocols.NewCompletedProt(maps.Values(md.KeySwitchOps))

	ownInputs := md.InputsFor[p.sess.NodeID]
	p.inputs = make(map[circuits.OperandLabel]*utils.Future[circuits.Input], len(ownInputs))
	for inLabel := range ownInputs {
		p.inputs[inLabel] = utils.NewFuture[circuits.Input]()
	}
	return
}

func (p *participantRuntime) Eval(ctx context.Context, c circuits.Circuit) error {

	go func() {
		for pd := range p.incpd {
			if err := p.CompleteMap.CompletedProtocol(pd); err != nil {
				panic(err)
			}
		}
	}()

	inChan, err := p.inputProvider(ctx, *p.sess, p.cd)
	if err != nil {
		return err
	}

	// processes the participant's inputs in a separate goroutine to
	// let the circuit run/network transfers begin in parallel
	go func() {
		for inOp := range inChan {
			fin, has := p.inputs[inOp.OperandLabel]
			if !has {
				p.Logf("skipping unexpected input %s", inOp.OperandLabel)
				continue
			}

			fin.Set(inOp)
		}
	}()

	err = c(p)
	if err != nil {
		return err
	}

	err = p.Wait()
	if err != nil {
		return err
	}

	close(p.incpd)

	return nil
}

func (p *participantRuntime) IncomingOperand(_ circuits.Operand) error {
	panic("participant should not receive incoming operands")
}

func (p *participantRuntime) GetOperand(ctx context.Context, opl circuits.OperandLabel) (*circuits.Operand, bool) {
	pkgct, err := p.trans.GetCiphertext(ctx, sessions.CiphertextID(opl))
	if err != nil {
		return nil, false
	}

	return &circuits.Operand{OperandLabel: opl, Ciphertext: &pkgct.Ciphertext}, true
}

func (p *participantRuntime) GetFutureOperand(ctx context.Context, opl circuits.OperandLabel) (*circuits.FutureOperand, bool) {

	fop := circuits.NewFutureOperand(opl)

	go func() {
		op, _ := p.GetOperand(ctx, opl)
		fop.Set(*op)
	}()

	return fop, true
}

func (p *participantRuntime) CompletedProtocol(pd protocols.Descriptor) error {
	p.incpd <- pd
	return nil
}

// Circuit Interface

func isValidPlaintext(in interface{}) bool {
	return isValidBGVPlaintextType(in) || isValidCKKSPlaintextType(in)
}

func isValidBGVPlaintextType(in interface{}) bool {
	switch in.(type) {
	case []uint64, []int64:
		return true
	default:
		return false

	}
}

func isValidCKKSPlaintextType(in interface{}) bool {
	switch in.(type) {
	case []complex128, []*bignum.Complex, []float64, []*big.Float:
		return true
	default:
		return false

	}
}

func (p *participantRuntime) waitForInputAndSend(opl circuits.OperandLabel, encryptor *rlwe.Encryptor) {
	fin, has := p.inputs[opl]
	if !has {
		panic(fmt.Errorf("called Input on non registered participant input: %s", opl))
	}

	// TODO: do rest in go routine (requires parallel encoders/encryptors)
	in := fin.Get()
	inct, err := p.processParticipantInput(in.OperandValue, encryptor)
	if err != nil {
		panic(err)
	}

	err = p.trans.PutCiphertext(p.ctx, sessions.Ciphertext{
		CiphertextMetadata: sessions.CiphertextMetadata{
			ID: sessions.CiphertextID(opl),
		},
		Ciphertext: *inct,
	})
	if err != nil {
		panic(err)
	}

	p.Logf("sent input %s", opl)
}

// Input reads an input operand with the given label from the context.
func (p *participantRuntime) Input(opl circuits.OperandLabel) *circuits.FutureOperand {

	opl = opl.ForCircuit(p.cd.CircuitID).ForMapping(p.cd.NodeMapping)

	if opl.NodeID() == p.sess.NodeID {
		p.waitForInputAndSend(opl, p.Encryptor.ShallowCopy())
	}

	return circuits.NewDummyFutureOperand(opl)
}

func (p *participantRuntime) InputSum(opl circuits.OperandLabel, nids ...sessions.NodeID) *circuits.FutureOperand {

	nids, err := circuits.ApplyNodeMapping(p.cd.NodeMapping, nids...)
	if err != nil {
		panic(err)
	}

	if len(nids) == 0 {
		nids = make([]sessions.NodeID, len(p.sess.Nodes))
		copy(nids, p.sess.Nodes)
	}

	opl = opl.ForCircuit(p.cd.CircuitID)

	if slices.Contains(nids, p.sess.NodeID) {
		sk, err := p.sess.GetSecretKeyForGroup(nids)
		if err != nil {
			panic(err)
		}
		var crs []byte
		crs = append(crs, p.sess.PublicSeed...)
		crs = append(crs, opl...)
		prng, err := sampling.NewKeyedPRNG(crs)
		if err != nil {
			panic(err)
		}

		p.waitForInputAndSend(opl.SetNode(p.sess.NodeID), p.Encryptor.ShallowCopy().WithKey(sk).WithPRNG(prng)) // TODO: remove second element
	}

	return circuits.NewDummyFutureOperand(opl)
}

// Load reads an existing ciphertext in the session
func (p *participantRuntime) Load(opl circuits.OperandLabel) *circuits.Operand {
	return &circuits.Operand{OperandLabel: opl}
}

func (p *participantRuntime) NewOperand(opl circuits.OperandLabel) *circuits.Operand {
	opl = opl.ForCircuit(p.cd.CircuitID).ForMapping(p.cd.NodeMapping)
	return &circuits.Operand{OperandLabel: opl}
}

func (p *participantRuntime) EvalLocal(needRlk bool, galKeys []uint64, f func(_ he.Evaluator) error) error {
	return nil
}

// DEC runs a DEC protocol over the provided operand within the context.
func (p *participantRuntime) DEC(in circuits.Operand, rec sessions.NodeID, params map[string]string) error {

	rec = p.cd.NodeMapping[string(rec)]
	if rec != p.sess.NodeID {
		return nil
	}

	pparams := maps.Clone(params)
	pparams["target"] = string(rec)
	pparams["op"] = string(in.OperandLabel)
	sig := protocols.Signature{Type: protocols.DEC, Args: pparams}

	pd, err := p.AwaitCompletedDescriptorFor(sig)
	if err != nil {
		return err
	}

	// queries the ct
	outLabel := keyOpOutputLabel(in.OperandLabel, sig)
	ct, err := p.trans.GetCiphertext(p.ctx, sessions.CiphertextID(outLabel))
	if err != nil {
		panic(err)
	}

	skg, err := p.sess.GetSecretKeyForGroup(pd.Participants)
	if err != nil {
		return err
	}

	decg := p.Decryptor.WithKey(skg)

	pt := rlwe.NewPlaintext(p.sess.Params, p.sess.Params.GetRLWEParameters().MaxLevel()) // TODO would be nice to call on Params directly
	decg.Decrypt(&ct.Ciphertext, pt)                                                     // TODO: bug in lattigo ShallowCopy/WithKey function: params not copied but needed by DecryptNew

	p.or <- circuits.Output{CircuitID: p.cd.CircuitID, Operand: circuits.Operand{OperandLabel: outLabel, Ciphertext: &rlwe.Ciphertext{Element: pt.Element}}}

	return nil
}

// PCKS runs a PCKS protocol over the provided operand within the context.
func (p *participantRuntime) PCKS(in circuits.Operand, rec sessions.NodeID, params map[string]string) error {
	panic("not implemented") // TODO: Implement
}

func (p *participantRuntime) Circuit() circuits.Descriptor {
	return p.cd.Clone()
}

// Parameters returns the encryption parameters for the circuit.
func (p *participantRuntime) Parameters() sessions.FHEParameters {
	return p.sess.Params
}

func (p *participantRuntime) Logf(msg string, v ...any) {
	log.Printf("%s | [%s] %s\n", p.sess.NodeID, p.cd.CircuitID, fmt.Sprintf(msg, v...))
}

func (p *participantRuntime) processParticipantInput(inputVal any, encryptor *rlwe.Encryptor) (inct *rlwe.Ciphertext, err error) {
	switch {
	case isValidPlaintext(inputVal):
		var inpt *rlwe.Plaintext
		switch enc := p.Encoder.(type) {
		case *bgv.Encoder:
			inpt = bgv.NewPlaintext(p.sess.Params.(bgv.Parameters), p.sess.Params.GetRLWEParameters().MaxLevel())
			err = enc.Encode(inputVal, inpt)
		case *ckks.Encoder:
			inpt = ckks.NewPlaintext(p.sess.Params.(ckks.Parameters), p.sess.Params.GetRLWEParameters().MaxLevel())
			err = enc.Encode(inputVal, inpt)
		}
		if err != nil {
			panic(fmt.Errorf("cannot encode input: %w", err))
		}
		inputVal = inpt
		fallthrough
	case isRLWEPLaintext(inputVal):
		inpt := inputVal.(*rlwe.Plaintext)
		inct, err := encryptor.EncryptNew(inpt)
		if err != nil {
			panic(err)
		}
		inputVal = inct
		fallthrough
	case isRLWECiphertext(inputVal):
		inct = inputVal.(*rlwe.Ciphertext)
	default:
		return nil, fmt.Errorf("invalid input type %T for session parameters of type %T", inputVal, p.sess.Parameters)
	}
	return inct, nil
}

func isRLWEPLaintext(in interface{}) bool {
	_, ok := in.(*rlwe.Plaintext)
	return ok
}

func isRLWECiphertext(in interface{}) bool {
	_, ok := in.(*rlwe.Ciphertext)
	return ok
}
