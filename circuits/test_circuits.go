package circuits

import (
	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
)

// TestCircuits contains a set of test circuits for the helium framework.
var TestCircuits map[Name]Circuit = map[Name]Circuit{
	"add-2-dec": func(ec Runtime) error {

		in1, in2 := ec.Input("//p1/in"), ec.Input("//p2/in")

		opRes := ec.NewOperand("//eval/sum")
		opRes.Ciphertext = bgv.NewCiphertext(ec.Parameters(), 1, ec.Parameters().MaxLevel())
		ec.Add(in1.Get().Ciphertext, in2.Get().Ciphertext, opRes.Ciphertext)

		return ec.DEC(opRes, "rec", map[string]string{
			"smudging": "40.0",
		})
	},

	"mul-2-dec": func(ec Runtime) error {

		in1, in2 := ec.Input("//p1/in"), ec.Input("//p2/in")

		opRes := ec.NewOperand("//eval/mul")
		opRes.Ciphertext = bgv.NewCiphertext(ec.Parameters(), 1, ec.Parameters().MaxLevel())
		ec.MulRelin(in1.Get().Ciphertext, in2.Get().Ciphertext, opRes.Ciphertext)

		return ec.DEC(opRes, "rec", map[string]string{
			"smudging": "40.0",
		})
	},
}
