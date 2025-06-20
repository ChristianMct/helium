package circuits

import (
	"testing"

	"github.com/ChristianMct/helium/sessions"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
)

func TestTestCircuitRuntime(t *testing.T) {
	require.Implements(t, (*Runtime)(nil), &TestRuntime{})

	bgvParamsLiteral := bgv.ParametersLiteral{
		LogN:             12,
		Q:                []uint64{0x7ffffffec001, 0x400000008001}, // 47 + 46 bits
		P:                []uint64{0xa001},                         // 15 bits
		PlaintextModulus: 65537,
	}

	ts, err := sessions.NewTestSession(2, 2, bgvParamsLiteral, "helper")
	if err != nil {
		t.Fatal(err)
	}

	params := ts.FHEParameters.(bgv.Parameters)

	// TODO: this test should check the operand labels

	ip := func(label OperandLabel) *rlwe.Plaintext {
		pt := bgv.NewPlaintext(params, params.MaxLevel())
		err := bgv.NewEncoder(params).Encode([]uint64{1}, pt)
		if err != nil {
			panic(err)
		}
		return pt
	}

	res := make(chan uint64, 1)
	or := func(output Output) {
		rec := make([]uint64, params.MaxSlots())
		pt := bgv.NewPlaintext(params, params.MaxLevel())
		pt.Value = output.Element.Value[0]
		err := bgv.NewEncoder(params).Decode(pt, rec)
		if err != nil {
			panic(err)
		}
		res <- rec[0]
	}

	cd := Descriptor{
		Signature: Signature{Name: "bgv-add-2-dec"},
		CircuitID: "test-circuit",
		Evaluator: "helper",
	}
	err = TestCircuits["bgv-add-2-dec"](NewTestRuntime(ts, cd, ip, or))
	require.NoError(t, err)
	require.Equal(t, uint64(2), <-res)

	cd = Descriptor{
		Signature: Signature{Name: "bgv-add-all-dec"},
		CircuitID: "test-circuit",
		Evaluator: "helper",
	}
	err = TestCircuits["bgv-add-all-dec"](NewTestRuntime(ts, cd, ip, or))
	require.NoError(t, err)
	require.Equal(t, uint64(2), <-res)

	close(res)
}
