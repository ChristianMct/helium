package pkg

import "github.com/tuneinsight/lattigo/v3/bfv"

type LocalCircuit struct {
	inputs, outputs []Operand
	Evaluate        func(bfv.Evaluator, chan Operand) chan Operand
}

type Operand struct {
	CiphertextID
	*bfv.Ciphertext
}

var ComponentWiseProduct4P = LocalCircuit{
	inputs:  []Operand{{CiphertextID: "node-0/in-0"}, {CiphertextID: "node-1/in-0"}, {CiphertextID: "node-2/in-0"}, {CiphertextID: "node-3/in-0"}},
	outputs: []Operand{{CiphertextID: "out-0"}},
	Evaluate: func(e bfv.Evaluator, in chan Operand) chan Operand {

		out := make(chan Operand)

		go func() {
			lvl2 := make(chan *bfv.Ciphertext, 2)

			op0, op1 := <-in, <-in

			go func() {
				res := e.ShallowCopy().MulNew(op0.Ciphertext, op1.Ciphertext)
				e.Relinearize(res, res)
				lvl2 <- res
			}()

			op2, op3 := <-in, <-in

			go func() {
				res := e.ShallowCopy().MulNew(op2.Ciphertext, op3.Ciphertext)
				e.Relinearize(res, res)
				lvl2 <- res
			}()

			res1, res2 := <-lvl2, <-lvl2
			res := e.MulNew(res1, res2)
			e.Relinearize(res, res)
			out <- Operand{CiphertextID: "out-0", Ciphertext: res}
		}()

		return out
	},
}
