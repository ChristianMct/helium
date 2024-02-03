package node

import (
	"fmt"
	"math"
	"strconv"
	"sync"

	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/services/compute"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v4/bgv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

// TestCircuits is a map mapping a circuitID string to each circuit function.
var TestCircuits = map[string]compute.Circuit{
	// "identity-1": func(ec compute.EvaluationContext) error {
	// 	opIn := ec.Input("//node-0/in-0")

	// 	opRes := pkg.Operand{OperandLabel: "//cloud/out-0", Ciphertext: opIn.Ciphertext}

	// 	params := ec.Parameters().Parameters
	// 	opOut, err := ec.DEC(opRes, map[string]string{
	// 		"target":   "node-0",
	// 		"lvl":      strconv.Itoa(params.MaxLevel()),
	// 		"smudging": "1.0",
	// 	})
	// 	if err != nil {
	// 		return err
	// 	}

	// 	ec.Output(opOut, "node-0")
	// 	return nil
	// },
	// "psi-2": func(ec compute.EvaluationContext) error {
	// 	return psiN(2, ec)
	// },
	// "psi-4": func(ec compute.EvaluationContext) error {
	// 	return psiN(4, ec)
	// },
	// "psi-8": func(ec compute.EvaluationContext) error {
	// 	return psiN(8, ec)
	// },
	// "psi-2-PCKS": func(ec compute.EvaluationContext) error {
	// 	opIn1 := ec.Input("//node-0/in-0")
	// 	opIn2 := ec.Input("//node-1/in-0")

	// 	res, _ := ec.MulNew(opIn1.Ciphertext, opIn2.Ciphertext)
	// 	ec.Relinearize(res, res)
	// 	opRes := pkg.Operand{OperandLabel: "//cloud/out-0", Ciphertext: res}

	// 	params := ec.Parameters().Parameters
	// 	opOut, err := ec.PCKS(opRes, map[string]string{
	// 		"target":   "node-R",
	// 		"lvl":      strconv.Itoa(params.MaxLevel()),
	// 		"smudging": "1.0",
	// 	})
	// 	if err != nil {
	// 		return err
	// 	}

	// 	ec.Output(opOut, "node-R")
	// 	return nil
	// },
	// "pir-3": func(ec compute.EvaluationContext) error {
	// 	return pirN(3, ec)
	// },
	// "pir-5": func(ec compute.EvaluationContext) error {
	// 	return pirN(5, ec)
	// },
	// "pir-9": func(ec compute.EvaluationContext) error {
	// 	return pirN(9, ec)
	// },

	"mul4-dec": func(e compute.EvaluationContext) error {

		inputs := make(chan pkg.Operand, 4)
		inOpls := utils.NewSet([]pkg.OperandLabel{"//light-0/in-0", "//light-1/in-0", "//light-2/in-0", "//light-3/in-0"})
		for inOpl := range inOpls {
			inOpl := inOpl
			go func() {
				inputs <- e.Input(inOpl)
			}()
		}

		op0 := <-inputs
		op1 := <-inputs

		lvl2 := make(chan *rlwe.Ciphertext, 2)
		go func() {
			ev := e.NewEvaluator()
			res, _ := ev.MulNew(op0.Ciphertext, op1.Ciphertext)
			ev.Relinearize(res, res)
			lvl2 <- res
		}()

		op2 := <-inputs
		op3 := <-inputs

		go func() {
			ev := e.NewEvaluator()
			res, _ := ev.MulNew(op2.Ciphertext, op3.Ciphertext)
			ev.Relinearize(res, res)
			lvl2 <- res
		}()

		res1, res2 := <-lvl2, <-lvl2
		res, _ := e.MulNew(res1, res2)
		e.Relinearize(res, res)

		params := e.Parameters().Parameters
		opres := pkg.Operand{OperandLabel: "//helper-0/res-0", Ciphertext: res}
		opout, err := e.DEC(opres, map[string]string{
			"target":   "helper-0",
			"lvl":      strconv.Itoa(params.MaxLevel()),
			"smudging": "40.0",
		})
		if err != nil {
			return err
		}

		e.Output(opout, "helper-0")

		return nil
	},

	"matmul4-dec": func(e compute.EvaluationContext) error {
		params := e.Parameters()

		m := params.PlaintextDimensions().Cols

		vecOp := e.Input(pkg.OperandLabel("//light-0/vec"))

		matOps := make(map[int]pkg.Operand)
		diagGalEl := make(map[int]uint64)
		for k := 0; k < m; k++ {
			matOps[k] = e.Load(pkg.OperandLabel(fmt.Sprintf("//helper-0/mat-diag-%d", k)))
			diagGalEl[k] = params.GaloisElement(k)
		}

		if vecOp.Ciphertext == nil { //TODO: this is only for the circuit parser to pass...
			vecOp.Ciphertext = bgv.NewCiphertext(params, 1, params.MaxLevelQ())
		}

		vecDecom := e.NewDecompQPBuffer()
		vecRotated := bgv.NewCiphertext(params, 1, params.MaxLevelQ())
		e.DecomposeNTT(params.MaxLevelQ(), params.MaxLevelP(), params.PCount(), vecOp.Value[1], true, vecDecom)
		ctres := rlwe.NewCiphertext(params, 2, params.MaxLevel())
		for di, d := range matOps {
			if err := e.AutomorphismHoisted(vecOp.LevelQ(), vecOp.Ciphertext, vecDecom, diagGalEl[di], vecRotated); err != nil {
				return err
			}
			e.MulThenAdd(vecRotated, d.Ciphertext, ctres)
		}
		if err := e.Relinearize(ctres, ctres); err != nil {
			return err
		}

		opres := pkg.Operand{OperandLabel: "//helper-0/res-0", Ciphertext: ctres}
		opout, err := e.DEC(opres, map[string]string{
			"target":   "helper-0",
			"lvl":      strconv.Itoa(params.MaxLevel()),
			"smudging": fmt.Sprintf("%f", float64(1<<40)),
		})
		if err != nil {
			return err
		}

		e.Output(opout, "helper-0")
		return nil
	},
}

var pirN = func(N int, ec compute.EvaluationContext) error {
	params := ec.Parameters()

	inops := make(chan struct {
		i    int
		op   pkg.Operand
		mask *rlwe.Plaintext
	}, N)

	reqOpChan := make(chan pkg.Operand, 1)

	inWorkers := &sync.WaitGroup{}
	inWorkers.Add(N)
	for i := 0; i < N; i++ {
		// each input is provided by a goroutine
		go func(i int) {
			encoder := bgv.NewEncoder(params)
			maskCoeffs := make([]uint64, params.N())
			maskCoeffs[i] = 1
			mask := bgv.NewPlaintext(params, params.MaxLevelQ())
			encoder.Encode(maskCoeffs, mask)

			opIn := ec.Input(pkg.OperandLabel(fmt.Sprintf("//node-%d/in-0", i)))

			if i != 0 {
				inops <- struct {
					i    int
					op   pkg.Operand
					mask *rlwe.Plaintext
				}{i, opIn, mask}
			} else {
				reqOpChan <- opIn
			}
			inWorkers.Done()
		}(i)
	}

	// close input channel when all input operands have been provided
	go func() {
		inWorkers.Wait()
		close(inops)
	}()

	// wait for the query ciphertext to be generated
	reqOp := <-reqOpChan

	// each received input operand can be processed by one of the NGoRoutine
	NGoRoutine := 8
	maskedOps := make(chan pkg.Operand, N)
	maskWorkers := &sync.WaitGroup{}
	maskWorkers.Add(NGoRoutine)
	for i := 0; i < NGoRoutine; i++ {
		go func() {
			evaluator := ec.NewEvaluator() // creates a shallow evaluator copy for this goroutine
			tmp := bgv.NewCiphertext(ec.Parameters(), 1, ec.Parameters().MaxLevel())
			for op := range inops {
				// 1) Multiplication of the query with the plaintext mask
				evaluator.Mul(reqOp.Ciphertext, op.mask, tmp)

				// 2) Inner sum (populate all the slots with the sum of all the slots)
				evaluator.InnerSum(tmp, 1, params.PlaintextSlots(), tmp)

				// 3) Multiplication of 2) with the i-th ciphertext stored in the cloud
				maskedCt, _ := evaluator.MulNew(tmp, op.op.Ciphertext)
				maskedOps <- pkg.Operand{Ciphertext: maskedCt}
			}
			maskWorkers.Done()
		}()
	}

	// close input processing channel when all input have been processed
	go func() {
		maskWorkers.Wait()
		close(maskedOps)
	}()

	evaluator := ec.NewEvaluator()
	tmpAdd := bgv.NewCiphertext(ec.Parameters(), 2, ec.Parameters().MaxLevel())
	c := 0
	for maskedOp := range maskedOps {
		evaluator.Add(maskedOp.Ciphertext, tmpAdd, tmpAdd)
		c++
	}

	ctRes := bgv.NewCiphertext(params, 1, tmpAdd.Level())
	evaluator.Relinearize(ctRes, tmpAdd)
	// output encrypted under CPK
	opRes := pkg.Operand{OperandLabel: "//cloud/out-0", Ciphertext: ctRes}

	opOut, err := ec.DEC(opRes, map[string]string{
		"target":   "node-0",
		"lvl":      strconv.Itoa(params.MaxLevel()),
		"smudging": "1.0",
	})
	if err != nil {
		return err
	}

	// output encrypted under node-a public key
	ec.Output(opOut, "node-0")
	return nil
}

// psiN computes the Private Set Intersection among N parties where N is a power of two.
var psiN = func(N int, ec compute.EvaluationContext) error {
	log2N := math.Log2(float64(N))
	if log2N != float64(int(log2N)) {
		return fmt.Errorf("psiN only implemented for powers of two, N = %d", N)
	}

	inOps := make(chan pkg.Operand, N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			inOps <- ec.Input(pkg.OperandLabel(fmt.Sprintf("//node-%d/in-0", i)))
		}()
	}

	// multiplication depth
	numLevels := int(log2N)

	chanForLevel := make([]chan pkg.Operand, numLevels+1)
	chanForLevel[0] = inOps
	// previousLevelChan := inOps

	for level := 1; level <= numLevels; level++ {
		level := level
		numMulForLevel := int(math.Pow(2, float64((numLevels-1)-(level-1))))
		chanForLevel[level] = make(chan pkg.Operand, numMulForLevel)
		for i := 0; i < numMulForLevel; i++ {
			go func() {
				ev1 := ec.NewEvaluator()
				op1 := <-chanForLevel[level-1]
				op2 := <-chanForLevel[level-1]
				res, _ := ev1.MulNew(op1.Ciphertext, op2.Ciphertext)
				ev1.Relinearize(res, res)
				chanForLevel[level] <- pkg.Operand{Ciphertext: res}
			}()
		}
	}

	resOp := <-chanForLevel[numLevels]
	opRes := pkg.Operand{OperandLabel: "//cloud/out-0", Ciphertext: resOp.Ciphertext}

	params := ec.Parameters().Parameters
	opOut, err := ec.DEC(opRes, map[string]string{
		"target":   "node-0",
		"lvl":      strconv.Itoa(params.MaxLevel()),
		"smudging": "1.0",
	})
	if err != nil {
		return err
	}

	ec.Output(opOut, "node-0")
	return nil
}
