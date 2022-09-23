package pkg

import (
	"fmt"
	"net/url"
	"path"

	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v3/bfv"
)

type Circuit interface {
	InputsLabels() []URL
	OutputsLabels() []URL
	InputsChannel() chan<- Operand
	OutputsChannel() <-chan Operand
	Expects(Operand) bool
	Expected() []Operand
	Evaluate() error
}

type LocalCircuit struct {
	LocalCircuitDef
	input     chan Operand
	output    chan Operand
	expected  utils.Set[URL]
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

func (lc *LocalCircuit) InputsChannel() chan<- Operand {
	return lc.input
}

func (lc *LocalCircuit) OutputsChannel() <-chan Operand {
	return lc.output
}

func (lc *LocalCircuit) Expects(op Operand) bool {
	return lc.expected.Contains(*op.URL)
}

func (lc *LocalCircuit) Expected() []Operand {
	els := make([]Operand, 0, len(lc.expected))
	for el := range lc.expected {
		el := el
		els = append(els, Operand{URL: &el})
	}
	return els

}

func (lc *LocalCircuit) Evaluate() error {
	return lc.f(lc.evaluator, lc.input, lc.output)
}

type LocalCircuitDef struct {
	Inputs, Outputs []URL
	Evaluate        func(eval bfv.Evaluator, in <-chan Operand, out chan<- Operand) error
}

func (lcd *LocalCircuitDef) InputsLabels() []URL {
	return lcd.Inputs // todo copy
}

func (lcd *LocalCircuitDef) OutputsLabels() []URL {
	return lcd.Outputs // todo copy
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

type OperandLabel string

type Operand struct {
	*URL
	*bfv.Ciphertext
}

var ComponentWiseProduct4P = LocalCircuitDef{
	Inputs:  []URL{*NewURL("//light-0/in-0"), *NewURL("//light-1/in-0"), *NewURL("//light-2/in-0"), *NewURL("//light-3/in-0")},
	Outputs: []URL{*NewURL("/out-0")},
	Evaluate: func(e bfv.Evaluator, in <-chan Operand, out chan<- Operand) error {

		lvl2 := make(chan *bfv.Ciphertext, 2)

		op0, op1 := <-in, <-in

		go func() {
			ev := e.ShallowCopy()
			res := ev.MulNew(op0.Ciphertext, op1.Ciphertext)
			ev.Relinearize(res, res)
			fmt.Println("computed lvl 1,1")
			lvl2 <- res
		}()

		op2, op3 := <-in, <-in

		go func() {
			ev := e.ShallowCopy()
			res := ev.MulNew(op2.Ciphertext, op3.Ciphertext)
			ev.Relinearize(res, res)
			fmt.Println("computed lvl 1,2")
			lvl2 <- res
		}()

		res1, res2 := <-lvl2, <-lvl2
		res := e.MulNew(res1, res2)
		e.Relinearize(res, res)
		fmt.Println("computed lvl 0")
		out <- Operand{URL: NewURL("/out-0"), Ciphertext: res}
		close(out)
		return nil
	},
}
