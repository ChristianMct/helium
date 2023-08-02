package compute

import (
	"strconv"
	"testing"

	"github.com/tuneinsight/lattigo/v4/rlwe"

	"github.com/ldsec/helium/pkg"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v4/bfv"
)

var ProdCKS Circuit = func(e EvaluationContext) error {

	inputSet := utils.NewSet([]pkg.OperandLabel{"//node-0/in-0", "//node-1/in-0", "//node-2/in-0", "//node-3/in-0"})

	lvl2 := make(chan *rlwe.Ciphertext, 2)

	ops := make(chan pkg.Operand, 4)
	for opl := range inputSet {
		opl := opl
		go func() {
			ops <- e.Input(opl)
		}()
	}

	op0 := <-ops
	op1 := <-ops

	go func() {
		ev := e.ShallowCopy()
		res := ev.MulNew(op0.Ciphertext, op1.Ciphertext)
		ev.Relinearize(res, res)
		lvl2 <- res
	}()

	op2 := <-ops
	op3 := <-ops

	go func() {
		ev := e.ShallowCopy()
		res := ev.MulNew(op2.Ciphertext, op3.Ciphertext)
		ev.Relinearize(res, res)
		lvl2 <- res
	}()

	res1, res2 := <-lvl2, <-lvl2
	res := e.MulNew(res1, res2)
	e.Relinearize(res, res)

	// cksCtx, _ := e.SubCircuit("CKS-0", CKS) // TODO pass operands with remapping. Unmapped become inputs ?
	// cksCtx.Set(pkg.Operand{OperandLabel: "/in-0", Ciphertext: res})
	// op := cksCtx.Get("/out-0")

	params := e.Parameters().Parameters
	opres := pkg.Operand{OperandLabel: "/res-0", Ciphertext: res}
	opout, err := e.DEC(opres, map[string]string{
		"target":   "node-0",
		"lvl":      strconv.Itoa(params.MaxLevel()),
		"smudging": "80.0",
	})
	if err != nil {
		return err
	}

	e.Output(opout, "node-0")

	return nil
}

func TestEvaluationContext(t *testing.T) {
	params, _ := bfv.NewParametersFromLiteral(bfv.PN13QP218)
	de := newCircuitParserCtx("PRODCKS-0", params, nil)
	if err := ProdCKS(de); err != nil {
		t.Error(err)
	}
}

func TestEvaluationContextWithNodeMapping(t *testing.T) {
	t.Skip() // TODO: test is failing
	params, _ := bfv.NewParametersFromLiteral(bfv.PN13QP218)
	nodeMap := map[string]pkg.NodeID{
		"node-0": "light-0",
		"node-1": "light-1",
		"node-2": "light-2",
		"node-3": "light-3",
	}
	de := newCircuitParserCtx("PRODCKS-0", params, nodeMap)
	if err := ProdCKS(de); err != nil {
		t.Error(err)
	}
}
