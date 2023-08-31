package main

import (
	"fmt"
	"math/big"
	"time"

	"github.com/tuneinsight/lattigo/v4/bgv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"gonum.org/v1/gonum/mat"
)

func main() {

	pl := bgv.ParametersLiteral{T: 1099511678977, LogN: 13, LogQ: []int{45, 45, 45}, LogP: []int{45}}

	printParamT(pl, 8)

	params, err := bgv.NewParametersFromLiteral(pl)
	if err != nil {
		panic(err)
	}

	fmt.Println("plaintext dim = ", params.PlaintextDimensions())

	m := params.PlaintextDimensions().Cols
	// Initialize two matrices, a and b.
	a := mat.NewDense(m, m, nil)
	a.Apply(func(i, j int, v float64) float64 {
		return float64(i) + float64(2*j)
	}, a)
	b := mat.NewVecDense(m, nil)
	b.SetVec(1, 1)
	r := mat.NewVecDense(m, nil)

	// fa := mat.Formatted(a, mat.Prefix("    "), mat.Squeeze())
	// fmt.Printf("a = %v\n", fa)

	diag := make(map[int][]uint64, m)
	for k := 0; k < m; k++ {
		diag[k] = make([]uint64, m)
		for i := 0; i < m; i++ {
			j := (i + k) % m
			diag[k][i] = uint64(a.At(i, j))
		}
	}

	rots := make([]int, 0)
	for di, d := range diag {
		//fmt.Printf("diag[%d] = %v\n", di, d)
		_ = d
		rots = append(rots, di)
	}

	// Take the matrix product of a and b and place the result in c.
	r.MulVec(a, b)
	fmt.Printf("r = %v\n", r.RawVector().Data)

	kgen := bgv.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()
	rlk, err := kgen.GenRelinearizationKeyNew(sk)
	check(err)

	rotToGalEl := make(map[int]uint64)
	galEls := params.GaloisElements(rots)
	for i, rot := range rots {
		rotToGalEl[rot] = galEls[i]
	}
	rtks, err := kgen.GenGaloisKeysNew(galEls, sk)
	check(err)

	encoder := bgv.NewEncoder(params)
	encryptor, err := bgv.NewEncryptor(params, pk)
	check(err)
	evaluator := bgv.NewEvaluator(params, rlwe.NewMemEvaluationKeySet(rlk, rtks...))
	decryptor, err := bgv.NewDecryptor(params, sk)
	check(err)

	fmt.Println("start eval")
	start := time.Now()
	pta := make(map[int]*rlwe.Plaintext)
	cta := make(map[int]*rlwe.Ciphertext)
	for di, d := range diag {
		pta[di] = rlwe.NewPlaintext(params, params.MaxLevel())
		encoder.Encode(d, pta[di])
		cta[di], err = encryptor.EncryptNew(pta[di])
		check(err)
	}

	ptb := rlwe.NewPlaintext(params, params.MaxLevel())
	bb := make([]uint64, len(b.RawVector().Data))
	for i, v := range b.RawVector().Data {
		bb[i] = uint64(v)
	}
	err = encoder.Encode(bb, ptb)
	check(err)
	ctb, err := encryptor.EncryptNew(ptb)
	check(err)

	ctbr := bgv.NewCiphertext(params, 1, params.MaxLevelQ())
	evaluator.DecomposeNTT(ctb.Level(), params.MaxLevelP(), params.PCount(), ctb.Value[1], true, evaluator.BuffDecompQP)
	ctres := rlwe.NewCiphertext(params, 2, params.MaxLevel())
	for di, d := range cta {
		err = evaluator.AutomorphismHoisted(ctb.LevelQ(), ctb, evaluator.BuffDecompQP, rotToGalEl[di], ctbr)
		check(err)
		evaluator.MulThenAdd(ctbr, d, ctres)
	}
	err = evaluator.Relinearize(ctres, ctres)
	check(err)

	fmt.Printf("done in %s\n", time.Since(start))

	ptres := decryptor.DecryptNew(ctres)
	res := make([]uint64, params.PlaintextSlots())
	encoder.Decode(ptres, res)
	fmt.Println("r =", res[:params.PlaintextDimensions().Cols])
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func printParamT(pl bgv.ParametersLiteral, minBitSize int) {
	var params bgv.Parameters
	var err error
	dims := make(map[int]int)
	for i := (1 << minBitSize) + 1; i <= 1<<(minBitSize+1); i += 2 {
		if !big.NewInt(int64(i)).ProbablyPrime(0) {
			continue
		}
		pl.T = uint64(i)
		params, err = bgv.NewParametersFromLiteral(pl)
		if err != nil {
			continue
		}
		dim := params.PlaintextDimensions().Cols
		if _, exists := dims[dim]; exists {
			continue
		}
		dims[dim] = i
		fmt.Println(i, dim)
	}
}
