package compute

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"testing"

	pkg "github.com/ldsec/helium/pkg/session"
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
		fmt.Println("computed lvl 1,1")
		lvl2 <- res
	}()

	op2 := <-ops
	op3 := <-ops

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

	// cksCtx, _ := e.SubCircuit("CKS-0", CKS) // TODO pass operands with remapping. Unmapped become inputs ?
	// cksCtx.Set(pkg.Operand{OperandLabel: "/in-0", Ciphertext: res})
	// op := cksCtx.Get("/out-0")

	params := e.Parameters().Parameters
	opres := pkg.Operand{OperandLabel: "/res-0", Ciphertext: res}
	opout, err := e.CKS("CKS-0", opres, map[string]interface{}{
		"target":     "node-0",
		"aggregator": "node-0",
		"lvl":        params.MaxLevel(),
		"smudging":   80.0,
	})
	if err != nil {
		return err
	}

	e.Output(opout)

	fmt.Println("received from CKS")
	return nil
}

func TestEvaluationContext(t *testing.T) {
	params, _ := bfv.NewParametersFromLiteral(bfv.PN13QP218)
	de := newCircuitParserCtx("PRODCKS-0", params, nil)
	ProdCKS(de)
	fmt.Println(de)
}

func TestEvaluationContextWithNodeMapping(t *testing.T) {
	params, _ := bfv.NewParametersFromLiteral(bfv.PN13QP218)
	nodeMap := map[string]pkg.NodeID{
		"node-0": "light-0",
		"node-1": "light-1",
		"node-2": "light-2",
		"node-3": "light-3",
	}
	de := newCircuitParserCtx("PRODCKS-0", params, nodeMap)
	ProdCKS(de)
	fmt.Println(de)
}

var CKS Circuit = func(e EvaluationContext) error {

	//cks := protocols.NewCKSProtocol(s, params["tsk"].(*rlwe.SecretKey), params["lvl"].(int), params["smudging"].(float64))

	op := e.Input("/in-0")

	_ = op
	fmt.Println(">eval CKS on", op.OperandLabel)

	opOut := pkg.Operand{OperandLabel: "/out-0"}

	e.Output(opOut)

	return nil
}
