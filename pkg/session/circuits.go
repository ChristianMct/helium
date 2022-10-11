package pkg

import (
	"net/url"
	"path"
	"sync"

	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v3/bfv"
)

type Circuit interface {
	InputsLabels() []OperandLabel
	OutputsLabels() []OperandLabel
	Inputs() chan<- Operand
	Outputs() <-chan Operand
	Expects(Operand) bool
	Expected() []Operand
	Evaluate() error
}

type FutureOperand struct {
	m        sync.Mutex
	op       *Operand
	awaiters []chan Operand
}

func (fop *FutureOperand) Await() <-chan Operand {
	fop.m.Lock()
	defer fop.m.Unlock()

	c := make(chan Operand, 1)
	if fop.op != nil {
		c <- *fop.op
	} else {
		fop.awaiters = append(fop.awaiters, c)
	}
	return c
}

func (fop *FutureOperand) Done(op Operand) {
	fop.m.Lock()
	defer fop.m.Unlock()
	if fop.op != nil {
		panic("Done called multiple times")
	}
	fop.op = &op
	for _, aw := range fop.awaiters {
		aw <- op // TODO copy ?
	}
}

type LocalCircuit struct {
	LocalCircuitDef
	input     chan Operand
	output    chan Operand
	expected  utils.Set[OperandLabel]
	evaluator bfv.Evaluator
	f         func(e bfv.Evaluator, in <-chan Operand, out chan<- Operand) error
}

func NewLocalCircuit(cDef LocalCircuitDef, ev bfv.Evaluator) *LocalCircuit {
	c := new(LocalCircuit)
	c.LocalCircuitDef = cDef
	c.input = make(chan Operand, len(cDef.Inputs))
	c.output = make(chan Operand, len(cDef.Outputs))
	c.expected = utils.NewSet(cDef.Inputs)
	c.evaluator = ev
	c.f = cDef.Evaluate
	return c
}

func (lc *LocalCircuit) Inputs() chan<- Operand {
	return lc.input
}

func (lc *LocalCircuit) Outputs() <-chan Operand {
	return lc.output
}

func (lc *LocalCircuit) Expects(op Operand) bool {
	return lc.expected.Contains(op.OperandLabel)
}

func (lc *LocalCircuit) Expected() []Operand {
	els := make([]Operand, 0, len(lc.expected))
	for el := range lc.expected {
		el := el
		els = append(els, Operand{OperandLabel: el})
	}
	return els

}

func (lc *LocalCircuit) Evaluate() error {
	return lc.f(lc.evaluator, lc.input, lc.output)
}

type OperandLabel string

type LocalCircuitDef struct {
	Name            string
	Inputs, Outputs []OperandLabel
	Evaluate        func(eval bfv.Evaluator, in <-chan Operand, out chan<- Operand) error
}

func (lcd *LocalCircuitDef) InputsLabels() []OperandLabel {
	ils := make([]OperandLabel, len(lcd.Inputs))
	copy(ils, lcd.Inputs)
	return ils
}

func (lcd *LocalCircuitDef) OutputsLabels() []OperandLabel {
	ols := make([]OperandLabel, len(lcd.Outputs))
	copy(ols, lcd.Outputs)
	return ols
}

// It seems that a central piece of the orchestration could be a good
// URL scheme for locating/designating ciphertexts
type URL url.URL

func ParseURL(s string) (*URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	return (*URL)(u), nil
}

func NewURL(s string) *URL {
	url, err := ParseURL(s)
	if err != nil {
		panic(err)
	}
	return url
}

func (u *URL) IsSessionWide() bool {
	return u.Host == ""
}

func (u *URL) CiphertextBaseID() CiphertextID {
	return CiphertextID(path.Base(u.Path))
}

func (u *URL) CiphertextID() CiphertextID {
	return CiphertextID(u.String())
}

func (u *URL) NodeID() NodeID {
	return NodeID(u.Host)
}

func (u *URL) String() string {
	return (*url.URL)(u).String()
}

type Operand struct {
	OperandLabel
	*bfv.Ciphertext
}
