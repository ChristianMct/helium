package circuits

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
	"github.com/tuneinsight/lattigo/v5/schemes/ckks"
)

// TestCircuits contains a set of test circuits for the helium framework.
// The circuits are pure encrypted functions; decryption of their outputs is
// requested separately by the application. Their required keys are inferred
// by symbolic execution, except for bgv-add-n which declares its interface.
var TestCircuits = map[Name]Circuit{

	// bgv-add-2 outputs the sum of the inputs of p1 and p2.
	"bgv-add-2": FromFunc(func(rt Runtime) error {
		params := rt.Parameters().(bgv.Parameters)
		in1, in2 := rt.Input("//p1/in"), rt.Input("//p2/in")
		out := rt.Output("out")

		res := bgv.NewCiphertext(params, 1, params.MaxLevel())
		if err := rt.Evaluator().Add(in1.Get().Ciphertext, in2.Get().Ciphertext, res); err != nil {
			return err
		}
		out.Set(res)
		return nil
	}),

	// bgv-mul-2 outputs the product of the inputs of p1 and p2.
	"bgv-mul-2": FromFunc(func(rt Runtime) error {
		params := rt.Parameters().(bgv.Parameters)
		in1, in2 := rt.Input("//p1/in"), rt.Input("//p2/in")
		out := rt.Output("out")

		res := bgv.NewCiphertext(params, 1, params.MaxLevel())
		if err := rt.Evaluator().MulRelin(in1.Get().Ciphertext, in2.Get().Ciphertext, res); err != nil {
			return err
		}
		out.Set(res)
		return nil
	}),

	// bgv-add-n outputs the sum of the inputs of p1 to pn, where n is a signature argument.
	// Its interface is declared explicitly.
	"bgv-add-n": {
		Interface: func(sig Signature) (Interface, error) {
			n, err := ArgumentOfType[int](sig, "n")
			if err != nil {
				return Interface{}, err
			}
			itf := Interface{Outputs: []string{"out"}}
			for i := 0; i < n; i++ {
				itf.Inputs = append(itf.Inputs, Port(fmt.Sprintf("//p%d/in", i+1)))
			}
			return itf, nil
		},
		Eval: func(rt Runtime) error {
			n, err := ArgumentOfType[int](rt.Descriptor().Signature, "n")
			if err != nil {
				return err
			}
			params := rt.Parameters().(bgv.Parameters)
			in := make([]*FutureOperand, n)
			for i := 0; i < n; i++ {
				in[i] = rt.Input(Port(fmt.Sprintf("//p%d/in", i+1)))
			}
			out := rt.Output("out")

			res := bgv.NewCiphertext(params, 1, params.MaxLevel())
			eval := rt.Evaluator()
			for i := 0; i < n; i++ {
				if err := eval.Add(in[i].Get().Ciphertext, res, res); err != nil {
					return err
				}
			}
			out.Set(res)
			return nil
		},
	},

	// bgv-add-all outputs the sum of the inputs of all the session nodes, as a summed input.
	"bgv-add-all": FromFunc(func(rt Runtime) error {
		sum := rt.InputSum("sum")
		out := rt.Output("out")
		out.Set(sum.Get().Ciphertext)
		return nil
	}),

	// bgv-rot-2 outputs the input of p1 rotated by k slots (a signature argument) plus the
	// input of p2 with its rows swapped. The Galois keys are inferred.
	"bgv-rot-2": FromFunc(rotate2),

	// bgv-innersum outputs the inner sum of 8 consecutive slots of the input of p1.
	"bgv-innersum": FromFunc(func(rt Runtime) error {
		params := rt.Parameters().(bgv.Parameters)
		in1 := rt.Input("//p1/in")
		out := rt.Output("out")

		res := bgv.NewCiphertext(params, 1, params.MaxLevel())
		if err := rt.Evaluator().InnerSum(in1.Get().Ciphertext, 1, 8, res); err != nil {
			return err
		}
		out.Set(res)
		return nil
	}),

	// ckks-add-2 outputs the sum of the inputs of p1 and p2.
	"ckks-add-2": FromFunc(func(rt Runtime) error {
		params := rt.Parameters().(ckks.Parameters)
		in1, in2 := rt.Input("//p1/in"), rt.Input("//p2/in")
		out := rt.Output("out")

		res := ckks.NewCiphertext(params, 1, params.MaxLevel())
		if err := rt.Evaluator().Add(in1.Get().Ciphertext, in2.Get().Ciphertext, res); err != nil {
			return err
		}
		out.Set(res)
		return nil
	}),

	// ckks-mul-2 outputs the product of the inputs of p1 and p2.
	"ckks-mul-2": FromFunc(func(rt Runtime) error {
		params := rt.Parameters().(ckks.Parameters)
		in1, in2 := rt.Input("//p1/in"), rt.Input("//p2/in")
		out := rt.Output("out")

		res := ckks.NewCiphertext(params, 1, params.MaxLevel())
		if err := rt.Evaluator().MulRelin(in1.Get().Ciphertext, in2.Get().Ciphertext, res); err != nil {
			return err
		}
		out.Set(res)
		return nil
	}),

	// ckks-rot-2 outputs the input of p1 rotated by k slots (a signature argument) plus the
	// conjugate of the input of p2. The Galois keys are inferred.
	"ckks-rot-2": FromFunc(rotate2),
}

// rotate2 is the scheme-agnostic evaluation function of the bgv-rot-2 and ckks-rot-2 circuits.
func rotate2(rt Runtime) error {
	k, err := ArgumentOfType[int](rt.Descriptor().Signature, "k")
	if err != nil {
		return err
	}
	in1, in2 := rt.Input("//p1/in"), rt.Input("//p2/in")
	out := rt.Output("out")

	eval := rt.Evaluator()
	rot, err := eval.RotateNew(in1.Get().Ciphertext, k)
	if err != nil {
		return err
	}
	conj, err := eval.ConjugateNew(in2.Get().Ciphertext)
	if err != nil {
		return err
	}
	if err := eval.Add(rot, conj, rot); err != nil {
		return err
	}
	out.Set(rot)
	return nil
}
