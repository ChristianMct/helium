package pkg

import (
	"net/url"
	"path"

	"github.com/tuneinsight/lattigo/v3/bfv"
)

type LocalCircuit struct {
	inputs, outputs []Operand
	Evaluate        func(bfv.Evaluator, chan Operand, chan Operand) error
}

func (c *LocalCircuit) Inputs() []Operand {
	return c.inputs // TODO copy
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

func (u *URL) CiphertextID() CiphertextID {
	return CiphertextID(path.Base(u.Path))
}

func (u *URL) NodeID() NodeID {
	return NodeID(u.Host)
}

type Operand struct {
	*URL
	*bfv.Ciphertext
}

var ComponentWiseProduct4P = LocalCircuit{
	inputs:  []Operand{{URL: NewURL("//node-0/in-0")}, {URL: NewURL("//node-1/in-0")}, {URL: NewURL("//node-2/in-0")}, {URL: NewURL("//node-3/in-0")}},
	outputs: []Operand{{URL: NewURL("/out-0")}},
	Evaluate: func(e bfv.Evaluator, in chan Operand, out chan Operand) error {

		go func() {
			lvl2 := make(chan *bfv.Ciphertext, 2)

			op0, op1 := <-in, <-in

			go func() {
				ev := e.ShallowCopy()
				res := ev.MulNew(op0.Ciphertext, op1.Ciphertext)
				ev.Relinearize(res, res)
				lvl2 <- res
			}()

			op2, op3 := <-in, <-in

			go func() {
				ev := e.ShallowCopy()
				res := ev.MulNew(op2.Ciphertext, op3.Ciphertext)
				ev.Relinearize(res, res)
				lvl2 <- res
			}()

			res1, res2 := <-lvl2, <-lvl2
			res := e.MulNew(res1, res2)
			e.Relinearize(res, res)
			out <- Operand{URL: NewURL("//node-1/in-0"), Ciphertext: res}
			close(out)
		}()

		return nil
	},
}
