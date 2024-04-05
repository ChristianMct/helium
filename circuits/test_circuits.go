package circuits

import (
	"github.com/tuneinsight/lattigo/v5/he"
	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
	"github.com/tuneinsight/lattigo/v5/schemes/ckks"
)

// TestCircuits contains a set of test circuits for the helium framework.
var TestCircuits map[Name]Circuit = map[Name]Circuit{
	"bgv-add-2-dec": func(ec Runtime) error {

		params := ec.Parameters().(bgv.Parameters)

		in1, in2 := ec.Input("//p1/in"), ec.Input("//p2/in")

		opRes := ec.NewOperand("//eval/sum")
		ec.EvalLocal(false, nil, func(eval he.Evaluator) error {
			opRes.Ciphertext = bgv.NewCiphertext(params, 1, params.MaxLevel())
			return eval.Add(in1.Get().Ciphertext, in2.Get().Ciphertext, opRes.Ciphertext)
		})

		return ec.DEC(*opRes, "rec", map[string]string{
			"smudging": "40.0",
		})
	},

	"bgv-mul-2-dec": func(ec Runtime) error {

		params := ec.Parameters().(bgv.Parameters)

		in1, in2 := ec.Input("//p1/in"), ec.Input("//p2/in")

		opRes := ec.NewOperand("//eval/mul")

		err := ec.EvalLocal(true, nil, func(eval he.Evaluator) error {
			opRes.Ciphertext = bgv.NewCiphertext(params, 1, params.MaxLevel())
			return eval.MulRelin(in1.Get().Ciphertext, in2.Get().Ciphertext, opRes.Ciphertext)
		})
		if err != nil {
			return err
		}

		return ec.DEC(*opRes, "rec", map[string]string{
			"smudging": "40.0",
		})
	},
	"ckks-add-2-dec": func(ec Runtime) error {

		params := ec.Parameters().(ckks.Parameters)

		in1, in2 := ec.Input("//p1/in"), ec.Input("//p2/in")

		opRes := ec.NewOperand("//eval/sum")
		ec.EvalLocal(false, nil, func(eval he.Evaluator) error {
			opRes.Ciphertext = ckks.NewCiphertext(params, 1, params.MaxLevel())
			return eval.Add(in1.Get().Ciphertext, in2.Get().Ciphertext, opRes.Ciphertext)
		})

		return ec.DEC(*opRes, "rec", map[string]string{
			"smudging": "40.0",
		})
	},

	"ckks-mul-2-dec": func(ec Runtime) error {

		params := ec.Parameters().(ckks.Parameters)

		in1, in2 := ec.Input("//p1/in"), ec.Input("//p2/in")

		opRes := ec.NewOperand("//eval/mul")

		err := ec.EvalLocal(true, nil, func(eval he.Evaluator) error {
			opRes.Ciphertext = ckks.NewCiphertext(params, 1, params.MaxLevel())
			if err := eval.MulRelin(in1.Get().Ciphertext, in2.Get().Ciphertext, opRes.Ciphertext); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}

		return ec.DEC(*opRes, "rec", map[string]string{
			"smudging": "10.0",
		})
	},
}
