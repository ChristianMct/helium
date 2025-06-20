package circuits

import (
	"fmt"
	"log"
	"sync"

	"github.com/ChristianMct/helium/sessions"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he"
	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
	"github.com/tuneinsight/lattigo/v5/schemes/ckks"
)

// TestRuntime is an implementation of the Runtime interface for testing purposes.
// It can be initialized from the FHE parameters and circuit inputs, then passed
// to a Circuit to execute it. It encrypts the requested inputs on-the-fly, under
// a test secret-key.
// See the Runtime interface.
type TestRuntime struct {
	sessions.TestSession

	cd             Descriptor
	inputProvider  func(OperandLabel) *rlwe.Plaintext
	outputReceiver func(Output)

	l         sync.Mutex
	evaluator he.Evaluator
}

// NewTestRuntime creates a new TestRuntime instance with the given FHE parameters and input/output functions.
func NewTestRuntime(tsess *sessions.TestSession, cd Descriptor, inputProvider func(OperandLabel) *rlwe.Plaintext, outputReceiver func(Output)) *TestRuntime {
	tr := &TestRuntime{TestSession: *tsess}
	tr.cd = cd

	tr.inputProvider = inputProvider
	tr.outputReceiver = outputReceiver

	tr.evaluator = sessions.NewEvaluator(tsess.FHEParameters, nil)

	return tr
}

func (tr *TestRuntime) CircuitDescriptor() Descriptor {
	return tr.cd
}

func (tr *TestRuntime) Parameters() sessions.FHEParameters {
	return tr.FHEParameters
}

func (tr *TestRuntime) Input(opl OperandLabel) *FutureOperand {
	tr.l.Lock()
	defer tr.l.Unlock()
	opl = opl.ForCircuit(tr.cd.CircuitID)
	fop := NewFutureOperand(opl)
	pt := tr.inputProvider(opl)
	if pt == nil {
		panic(fmt.Errorf("input provider returned nil input for %s", opl))
	}
	ct, err := tr.Encryptor.EncryptNew(pt)
	if err != nil {
		panic(err)
	}
	fop.Set(Operand{Ciphertext: ct, OperandLabel: opl})
	return fop
}

func (tr *TestRuntime) InputSum(opl OperandLabel, nodeIDs ...sessions.NodeID) *FutureOperand {
	tr.l.Lock()
	defer tr.l.Unlock()

	fop := NewFutureOperand(opl)

	opls, err := ExpandInputSumLabels(opl, tr.HelperSession, tr.cd.CircuitID, nodeIDs...)
	if err != nil {
		panic(err)
	}

	ptAgg := rlwe.NewPlaintext(tr.RlweParams)
	for _, opl := range opls {
		pt := tr.inputProvider(opl)
		if pt == nil {
			panic(fmt.Errorf("input provider returned nil input for %s", opl))
		}
		tr.RlweParams.RingQ().Add(ptAgg.Value, pt.Value, ptAgg.Value)
		*ptAgg.MetaData = *pt.MetaData
	}
	ct, err := tr.Encryptor.EncryptNew(ptAgg) //TODO: simulate CRS-based encryption
	if err != nil {
		panic(err)
	}
	fop.Set(Operand{Ciphertext: ct, OperandLabel: opl})
	return fop
}

func (tr *TestRuntime) Load(_ OperandLabel) *Operand {
	panic("not implemented") // TODO: Implement
}

func (tr *TestRuntime) NewOperand(opl OperandLabel) *Operand {
	return &Operand{OperandLabel: opl.ForCircuit(tr.cd.CircuitID)}
}

func (tr *TestRuntime) EvalLocal(needRlk bool, galKeys []uint64, f func(he.Evaluator) error) error {

	var rlk *rlwe.RelinearizationKey
	gks := make([]*rlwe.GaloisKey, len(galKeys))

	if needRlk {
		rlk = tr.KeyGen.GenRelinearizationKeyNew(tr.SkIdeal)
	}
	for i, gk := range galKeys {
		gks[i] = tr.KeyGen.GenGaloisKeyNew(gk, tr.SkIdeal)
	}

	evks := rlwe.NewMemEvaluationKeySet(rlk, gks...)
	var ev he.Evaluator
	switch sev := tr.evaluator.(type) {
	case *bgv.Evaluator:
		ev = sev.WithKey(evks)
	case *ckks.Evaluator:
		ev = sev.WithKey(evks)
	default:
		panic("unsupported evaluator type")
	}
	return f(ev)
}

func (tr *TestRuntime) DEC(in Operand, rec sessions.NodeID, params map[string]string) error {
	tr.l.Lock()
	defer tr.l.Unlock()
	pt := tr.Decryptor.DecryptNew(in.Ciphertext)
	tr.outputReceiver(Output{Operand: Operand{OperandLabel: OperandLabel(fmt.Sprintf("%s-dec", in.OperandLabel)), Ciphertext: &rlwe.Ciphertext{Element: pt.Element}}, CircuitID: tr.cd.CircuitID})
	return nil
}

func (tr *TestRuntime) PCKS(in Operand, rec sessions.NodeID, params map[string]string) error {
	panic("not implemented") // TODO: Implement
}

func (tr *TestRuntime) Logf(msg string, v ...any) {
	log.Printf("[TestRuntime] %s\n", fmt.Sprintf(msg, v...))
}
