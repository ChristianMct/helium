package compute

import (
	"context"
	"fmt"
	"sync"

	"golang.org/x/exp/maps"

	"github.com/ldsec/helium/pkg/circuits"
	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/protocols"
	"github.com/tuneinsight/lattigo/v4/bgv"
	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe/ringqp"
)

type completedProt struct {
	wg              sync.WaitGroup
	completedProtMu sync.RWMutex
	completedProt   map[string]chan protocols.Descriptor
}

func newCompletedProt(sigs []protocols.Signature) *completedProt {
	cp := new(completedProt)
	cp.completedProt = make(map[string]chan protocols.Descriptor)
	for _, sig := range sigs {
		cp.completedProt[sig.String()] = make(chan protocols.Descriptor, 1)
	}
	cp.wg.Add(len(sigs))
	return cp
}

func (p *completedProt) CompletedProtocol(pd protocols.Descriptor) error {
	p.completedProtMu.Lock()
	pdc, expected := p.completedProt[pd.Signature.String()]
	p.completedProtMu.Unlock()
	if !expected {
		return fmt.Errorf("unexpected completed descriptor for signature: %s", pd.Signature)
	}

	pdc <- pd

	p.wg.Done()
	return nil
}

func (p *completedProt) AwaitCompletedDescriptorFor(sig protocols.Signature) (pdp *protocols.Descriptor, err error) {
	p.completedProtMu.RLock()
	incDesc, has := p.completedProt[sig.String()]
	p.completedProtMu.RUnlock()
	if !has {
		return nil, fmt.Errorf("not waiting for completed protocol for sig %s", sig)
	}

	pd := <-incDesc
	return &pd, nil
}

func (p *completedProt) Wait() error {
	p.wg.Wait()
	return nil // TODO error here ?
}

type participant struct {
	ctx           context.Context // TODO: check if storing this context this way is a problem
	cd            circuits.Descriptor
	sess          *pkg.Session
	inputProvider InputProvider
	cpk           rlwe.PublicKey
	trans         Transport
	or            OutputReceiver

	*completedProt
	dummyEvaluator
}

func NewParticipant(ctx context.Context, cd circuits.Descriptor, ci *circuits.Info, sess *pkg.Session, ip InputProvider, cpk rlwe.PublicKey, trans Transport, or OutputReceiver) (*participant, error) {
	return &participant{
		ctx:           ctx,
		cd:            cd,
		sess:          sess,
		inputProvider: ip,
		cpk:           cpk,
		or:            or,
		trans:         trans,
		completedProt: newCompletedProt(maps.Values(ci.KeySwitchOps)),
	}, nil
}

// Service interface

func (p *participant) IncomingOperand(_ circuits.Operand) error {
	panic("participant should not receive incoming operands")
}

func (p *participant) GetOperand(ctx context.Context, opl circuits.OperandLabel) (*circuits.Operand, bool) {
	pkgct, err := p.trans.GetCiphertext(ctx, pkg.CiphertextID(opl))
	if err != nil {
		return nil, false
	}

	return &circuits.Operand{OperandLabel: opl, Ciphertext: &pkgct.Ciphertext}, true
}

func (p *participant) GetFutureOperand(ctx context.Context, opl circuits.OperandLabel) (*circuits.FutureOperand, bool) {

	fop := circuits.NewFutureOperand(opl)

	go func() {
		op, _ := p.GetOperand(ctx, opl)
		fop.Set(*op)
	}()

	return fop, true
}

// Circuit Interface

// Input reads an input operand with the given label from the context.
func (p *participant) Input(opl circuits.OperandLabel) *circuits.FutureOperand {

	opl = opl.ForCircuit(p.cd.ID).ForMapping(p.cd.NodeMapping)

	if opl.Host() != p.sess.NodeID {
		return circuits.NewDummyFutureOperand(opl)
	}

	in, err := p.inputProvider(p.ctx, opl)
	if err != nil {
		panic(fmt.Errorf("could not get inputs from input provider: %w", err)) // TODO return error
	}

	enc, err := rlwe.NewEncryptor(p.sess.Params, &p.cpk) // TODO: Encryptor-provider interface instead of passing cpk
	if err != nil {
		panic(err)
	}

	ct, err := enc.EncryptNew(in)
	if err != nil {
		panic(err)
	}

	err = p.trans.PutCiphertext(p.ctx, pkg.Ciphertext{Ciphertext: *ct, CiphertextMetadata: pkg.CiphertextMetadata{ID: pkg.CiphertextID(opl)}})
	if err != nil {
		panic(err)
	}

	return circuits.NewDummyFutureOperand(opl)
}

// Load reads an existing ciphertext in the session
func (p *participant) Load(opl circuits.OperandLabel) *circuits.Operand {
	return &circuits.Operand{OperandLabel: opl}
}

func (p *participant) NewOperand(opl circuits.OperandLabel) circuits.Operand {
	opl = opl.ForCircuit(p.cd.ID).ForMapping(p.cd.NodeMapping)
	return circuits.Operand{OperandLabel: opl}
}

// Set registers the given operand to the context.
func (p *participant) Set(_ circuits.Operand) {
	panic("not implemented") // TODO: Remove this method altoghether
}

// Output outputs the given operand to the context.
func (p *participant) Output(op circuits.Operand, nid pkg.NodeID) {
	if nid != p.sess.NodeID {
		return
	}

	ct, err := p.trans.GetCiphertext(p.ctx, pkg.CiphertextID(op.OperandLabel))
	if err != nil {
		panic(err)
	}

	p.or <- circuits.Output{ID: p.cd.ID, Operand: circuits.Operand{OperandLabel: op.OperandLabel, Ciphertext: &ct.Ciphertext}}
}

// DEC runs a DEC protocol over the provided operand within the context.
func (p *participant) DEC(in circuits.Operand, rec pkg.NodeID, params map[string]string) error {

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
	ct, err := p.trans.GetCiphertext(p.ctx, pkg.CiphertextID(outLabel))
	if err != nil {
		panic(err)
	}

	sk, err := p.sess.GetSecretKeyForGroup(pd.Participants)
	if err != nil {
		return err
	}

	dec, err := rlwe.NewDecryptor(p.sess.Params, sk)
	if err != nil {
		return err
	}

	pt := dec.DecryptNew(&ct.Ciphertext)

	p.or <- circuits.Output{ID: p.cd.ID, Operand: circuits.Operand{OperandLabel: outLabel, Ciphertext: &rlwe.Ciphertext{Operand: pt.Operand}}}

	return nil
}

// PCKS runs a PCKS protocol over the provided operand within the context.
func (p *participant) PCKS(in circuits.Operand, rec pkg.NodeID, params map[string]string) error {
	panic("not implemented") // TODO: Implement
}

// Parameters returns the encryption parameters for the circuit.
func (p *participant) Parameters() bgv.Parameters {
	return *p.sess.Params
}

type dummyEvaluator struct{}

func (de *dummyEvaluator) Add(op0 *rlwe.Ciphertext, op1 interface{}, opOut *rlwe.Ciphertext) (err error) {
	return nil
}

func (de *dummyEvaluator) Sub(op0 *rlwe.Ciphertext, op1 interface{}, opOut *rlwe.Ciphertext) (err error) {
	return nil
}

func (de *dummyEvaluator) Mul(op0 *rlwe.Ciphertext, op1 interface{}, opOut *rlwe.Ciphertext) (err error) {
	return nil
}

func (de *dummyEvaluator) MulNew(op0 *rlwe.Ciphertext, op1 interface{}) (opOut *rlwe.Ciphertext, err error) {
	return nil, nil
}

func (de *dummyEvaluator) MulRelin(op0 *rlwe.Ciphertext, op1 interface{}, opOut *rlwe.Ciphertext) (err error) {
	return nil
}

func (de *dummyEvaluator) MulRelinNew(op0 *rlwe.Ciphertext, op1 interface{}) (opOut *rlwe.Ciphertext, err error) {
	return nil, nil
}

func (de *dummyEvaluator) MulThenAdd(op0 *rlwe.Ciphertext, op1 interface{}, opOut *rlwe.Ciphertext) (err error) {
	return nil
}

func (de *dummyEvaluator) Relinearize(op0 *rlwe.Ciphertext, op1 *rlwe.Ciphertext) (err error) {
	return nil
}

func (de *dummyEvaluator) Rescale(op0 *rlwe.Ciphertext, op1 *rlwe.Ciphertext) (err error) {
	return nil
}

func (de *dummyEvaluator) InnerSum(ctIn *rlwe.Ciphertext, batchSize int, n int, opOut *rlwe.Ciphertext) (err error) {
	return nil
}

func (de *dummyEvaluator) AutomorphismHoisted(level int, ctIn *rlwe.Ciphertext, c1DecompQP []ringqp.Poly, galEl uint64, opOut *rlwe.Ciphertext) (err error) {
	return nil
}

func (de *dummyEvaluator) DecomposeNTT(levelQ int, levelP int, nbPi int, c2 ring.Poly, c2IsNTT bool, decompQP []ringqp.Poly) {
}

func (de *dummyEvaluator) NewDecompQPBuffer() []ringqp.Poly {
	return nil
}

func (de *dummyEvaluator) NewEvaluator() circuits.Evaluator {
	return de
}
