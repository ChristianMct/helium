package compute

import (
	"context"
	"fmt"
	"math/big"

	"golang.org/x/exp/maps"

	"github.com/ChristianMct/helium/circuits"
	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/sessions"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he"
	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
	"github.com/tuneinsight/lattigo/v5/schemes/ckks"
	"github.com/tuneinsight/lattigo/v5/utils/bignum"
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
}

// Service interface

func (p *participantRuntime) Init(ctx context.Context, md circuits.Metadata) (err error) {

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

	err := c(p)
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

// Input reads an input operand with the given label from the context.
func (p *participantRuntime) Input(opl circuits.OperandLabel) *circuits.FutureOperand {

	opl = opl.ForCircuit(p.cd.CircuitID).ForMapping(p.cd.NodeMapping)

	if opl.NodeID() != p.sess.NodeID {
		return circuits.NewDummyFutureOperand(opl)
	}

	in, err := p.inputProvider(p.ctx, p.cd.CircuitID, opl, *p.sess)
	if err != nil {
		panic(fmt.Errorf("could not get inputs from input provider: %w", err)) // TODO return error
	}

	var inct sessions.Ciphertext
	switch {
	case isValidPlaintext(in):
		var inpt *rlwe.Plaintext
		switch enc := p.Encoder.(type) {
		case *bgv.Encoder:
			inpt = bgv.NewPlaintext(p.sess.Params.(bgv.Parameters), p.sess.Params.GetRLWEParameters().MaxLevel())
			err = enc.Encode(in, inpt)
		case *ckks.Encoder:
			inpt = ckks.NewPlaintext(p.sess.Params.(ckks.Parameters), p.sess.Params.GetRLWEParameters().MaxLevel())
			err = p.Encoder.(*ckks.Encoder).Encode(in, inpt)
		}
		if err != nil {
			panic(fmt.Errorf("cannot encode input: %w", err))
		}
		in = inpt
		fallthrough
	case isRLWEPLaintext(in):
		inpt := in.(*rlwe.Plaintext)
		inct, err := p.EncryptNew(inpt)
		if err != nil {
			panic(err)
		}
		in = inct
		fallthrough
	case isRLWECiphertext(in):
		inct = sessions.Ciphertext{
			Ciphertext:         *in.(*rlwe.Ciphertext),
			CiphertextMetadata: sessions.CiphertextMetadata{ID: sessions.CiphertextID(opl)},
		}
	default:
		panic(fmt.Errorf("invalid input type %T for session parameters of type %T", in, p.sess.Parameters))
	}

	err = p.trans.PutCiphertext(p.ctx, inct)
	if err != nil {
		panic(err)
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

// Parameters returns the encryption parameters for the circuit.
func (p *participantRuntime) Parameters() sessions.FHEParameters {
	return p.sess.Params
}

func isRLWEPLaintext(in interface{}) bool {
	_, ok := in.(*rlwe.Plaintext)
	return ok
}

func isRLWECiphertext(in interface{}) bool {
	_, ok := in.(*rlwe.Ciphertext)
	return ok
}
