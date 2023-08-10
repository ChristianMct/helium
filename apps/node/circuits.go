package main

import (
	"fmt"
	"math"
	"strconv"
	"sync"

	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/services/compute"
	"github.com/tuneinsight/lattigo/v4/bgv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

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

// testCircuits is a map mapping a circuitID string to each circuit function.
var testCircuits = map[string]compute.Circuit{
	"identity-1": func(ec compute.EvaluationContext) error {
		opIn := ec.Input("//node-0/in-0")

		opRes := pkg.Operand{OperandLabel: "//cloud/out-0", Ciphertext: opIn.Ciphertext}

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
	},
	"psi-2": func(ec compute.EvaluationContext) error {
		return psiN(2, ec)
	},
	"psi-4": func(ec compute.EvaluationContext) error {
		return psiN(4, ec)
	},
	"psi-8": func(ec compute.EvaluationContext) error {
		return psiN(8, ec)
	},
	"psi-2-PCKS": func(ec compute.EvaluationContext) error {
		opIn1 := ec.Input("//node-0/in-0")
		opIn2 := ec.Input("//node-1/in-0")

		res, _ := ec.MulNew(opIn1.Ciphertext, opIn2.Ciphertext)
		ec.Relinearize(res, res)
		opRes := pkg.Operand{OperandLabel: "//cloud/out-0", Ciphertext: res}

		params := ec.Parameters().Parameters
		opOut, err := ec.PCKS(opRes, map[string]string{
			"target":   "node-R",
			"lvl":      strconv.Itoa(params.MaxLevel()),
			"smudging": "1.0",
		})
		if err != nil {
			return err
		}

		ec.Output(opOut, "node-R")
		return nil
	},
	"pir-3": func(ec compute.EvaluationContext) error {
		return pirN(3, ec)
	},
	"pir-5": func(ec compute.EvaluationContext) error {
		return pirN(5, ec)
	},
	"pir-9": func(ec compute.EvaluationContext) error {
		return pirN(9, ec)
	},
}
