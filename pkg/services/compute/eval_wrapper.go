package compute

import (
	"github.com/tuneinsight/lattigo/v4/bgv"
	"github.com/tuneinsight/lattigo/v4/rlwe/ringqp"
)

type EvaluatorWrapper struct {
	*bgv.Evaluator
}

func (ew *EvaluatorWrapper) NewDecompQPBuffer() []ringqp.Poly {
	params := ew.Parameters()
	decompRNS := params.DecompRNS(params.MaxLevelQ(), 0)
	ringQP := params.RingQP()
	buffDecompQP := make([]ringqp.Poly, decompRNS)
	for i := 0; i < decompRNS; i++ {
		buffDecompQP[i] = ringQP.NewPoly()
	}
	return buffDecompQP
}
