package helium_test

import (
	"fmt"
	"testing"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/heliumtest"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

var bgvParamsLiteral = bgv.ParametersLiteral{
	LogN:             12,
	Q:                []uint64{0x7ffffffec001, 0x400000008001}, // 47 + 46 bits
	P:                []uint64{0xa001},                         // 15 bits
	PlaintextModulus: 65537,
}

func TestParse(t *testing.T) {
	ts, err := heliumtest.NewSessions(2, 2, bgvParamsLiteral, "helper")
	require.NoError(t, err)
	params := ts.FHEParameters.(bgv.Parameters)

	rotKeys := helium.Keys{}.Merge(helium.Keys{GaloisEls: []uint64{params.GaloisElement(3), params.GaloisElementOrderTwoOrthogonalSubgroup()}})
	innerSumKeys := helium.Keys{}.Merge(helium.Keys{GaloisEls: rlwe.GaloisElementsForInnerSum(params, 1, 8)})
	expected := []struct {
		sig helium.Signature
		itf helium.Interface
	}{
		{helium.Signature{Name: "bgv-add-2"}, helium.Interface{Inputs: []helium.Port{"//p1/in", "//p2/in"}, Outputs: []string{"out"}}},
		{helium.Signature{Name: "bgv-mul-2"}, helium.Interface{Inputs: []helium.Port{"//p1/in", "//p2/in"}, Outputs: []string{"out"}, Keys: helium.Keys{Rlk: true}}},
		{helium.Signature{Name: "bgv-add-all"}, helium.Interface{SumInputs: []helium.SumPort{{Name: "sum"}}, Outputs: []string{"out"}}},
		{helium.Signature{Name: "bgv-rot-2", Args: map[string]string{"k": "3"}}, helium.Interface{Inputs: []helium.Port{"//p1/in", "//p2/in"}, Outputs: []string{"out"}, Keys: rotKeys}},
		{helium.Signature{Name: "bgv-innersum"}, helium.Interface{Inputs: []helium.Port{"//p1/in"}, Outputs: []string{"out"}, Keys: innerSumKeys}},
	}
	for _, c := range expected {
		itf, err := heliumtest.Circuits[c.sig.Name].Describe(c.sig, ts.FHEParameters)
		require.NoError(t, err, c.sig)
		require.Equal(t, c.itf, itf, c.sig)
	}

	// explicit interface
	itf, err := heliumtest.Circuits["bgv-add-n"].Describe(helium.Signature{Name: "bgv-add-n", Args: map[string]string{"n": "3"}}, ts.FHEParameters)
	require.NoError(t, err)
	require.Equal(t, helium.Interface{Inputs: []helium.Port{"//p1/in", "//p2/in", "//p3/in"}, Outputs: []string{"out"}}, itf)

	// explicitly declared keys are merged with the inferred ones
	itf, err = helium.Parse(func(rt helium.CircuitRuntime) error {
		rt.Keys(helium.Keys{GaloisEls: []uint64{5}})
		in := rt.Input("//p1/in")
		out := rt.Output("out")
		res, err := rt.Evaluator().MulRelinNew(in.Get().Ciphertext, in.Get().Ciphertext)
		out.Set(res)
		return err
	}, helium.Signature{Name: "merged-keys"}, ts.FHEParameters)
	require.NoError(t, err)
	require.Equal(t, helium.Keys{Rlk: true, GaloisEls: []uint64{5}}, itf.Keys)

	// placeholders track the degree and level of the ciphertexts
	var shapes []string
	shape := func(ct *rlwe.Ciphertext) { shapes = append(shapes, fmt.Sprintf("%d@%d", ct.Degree(), ct.Level())) }
	_, err = helium.Parse(func(rt helium.CircuitRuntime) error {
		in := rt.Input("//p1/in")
		out := rt.Output("out")
		eval := rt.Evaluator()
		ct := in.Get().Ciphertext
		shape(ct)
		prod, _ := eval.MulNew(ct, ct)
		shape(prod)
		require.NoError(t, eval.Relinearize(prod, prod))
		shape(prod)
		require.NoError(t, eval.Rescale(prod, prod))
		shape(prod)
		out.Set(prod)
		return nil
	}, helium.Signature{Name: "shapes"}, ts.FHEParameters)
	require.NoError(t, err)
	maxLevel := params.MaxLevel()
	require.Equal(t, []string{
		fmt.Sprintf("1@%d", maxLevel), fmt.Sprintf("2@%d", maxLevel), fmt.Sprintf("1@%d", maxLevel), fmt.Sprintf("1@%d", maxLevel-1),
	}, shapes)

	// parsing errors
	_, err = helium.Parse(func(rt helium.CircuitRuntime) error { rt.Input("//p1/in"); return nil }, helium.Signature{Name: "no-output"}, ts.FHEParameters)
	require.Error(t, err, "a circuit must declare an output")
	_, err = helium.Parse(func(rt helium.CircuitRuntime) error { rt.Output("out"); return fmt.Errorf("boom") }, helium.Signature{Name: "failing"}, ts.FHEParameters)
	require.Error(t, err, "errors are reported")
	_, err = helium.Parse(func(rt helium.CircuitRuntime) error { rt.Input("bad"); rt.Output("out"); return nil }, helium.Signature{Name: "bad-port"}, ts.FHEParameters)
	require.Error(t, err, "ports are validated")
	_, err = helium.Parse(func(rt helium.CircuitRuntime) error { rt.Output("out"); return nil }, helium.Signature{Name: "unset-output"}, ts.FHEParameters)
	require.ErrorContains(t, err, "never set", "outputs must be set")
	_, err = helium.Parse(func(rt helium.CircuitRuntime) error {
		in := rt.Input("//p1/in")
		rt.Output("out").Set(in.Get().Ciphertext)
		_ = rt.Evaluator().Scheme().(*bgv.Evaluator)
		return nil
	}, helium.Signature{Name: "scheme"}, ts.FHEParameters)
	require.ErrorContains(t, err, "scheme evaluator", "the scheme evaluator is not available")
}

func TestResolve(t *testing.T) {
	itf := helium.Interface{Inputs: []helium.Port{"//p1/in", "//p2/in"}, SumInputs: []helium.SumPort{{Name: "sum"}}, Outputs: []string{"out"}}
	nodes := []helium.NodeID{"node-0", "node-1", "node-2"}
	cd := helium.Descriptor{
		Signature:   helium.Signature{Name: "c"},
		CircuitID:   "c-0",
		NodeMapping: map[string]helium.NodeID{"p1": "node-0", "p2": "node-1"},
		Evaluator:   "helper",
	}

	md, err := helium.Resolve(cd, itf, nodes)
	require.NoError(t, err)
	require.Equal(t, map[helium.OperandID]helium.Port{"//node-0/c-0/in": "//p1/in", "//node-1/c-0/in": "//p2/in"}, md.Inputs)
	require.Equal(t, map[string][]helium.OperandID{"sum": {"//node-0/c-0/sum", "//node-1/c-0/sum", "//node-2/c-0/sum"}}, md.SumInputs)
	require.Equal(t, map[string]helium.OperandID{"out": "//helper/c-0/out"}, md.Outputs)
	require.Equal(t, nodes, md.Participants)
	require.Equal(t, []helium.OperandID{"//node-0/c-0/in", "//node-0/c-0/sum"}, md.InputsOf["node-0"])
	require.Equal(t, []helium.OperandID{"//node-2/c-0/sum"}, md.InputsOf["node-2"])
	require.True(t, md.IsParticipant("node-2"))
	require.False(t, md.IsParticipant("helper"))
	require.True(t, md.IsEvaluator("helper"))
	id, has := md.InputID("//p2/in")
	require.True(t, has)
	require.Equal(t, helium.OperandID("//node-1/c-0/in"), id)
	require.Len(t, md.ExpectedInputs(), 5)

	// operand ids
	require.Equal(t, helium.NodeID("node-1"), id.NodeID())
	require.Equal(t, helium.CircuitID("c-0"), id.CircuitID())
	require.Equal(t, "in", id.Name())
	require.Error(t, helium.OperandID("//node/in").Validate())

	// errors
	_, err = helium.Resolve(cd, helium.Interface{Inputs: []helium.Port{"//p3/in"}, Outputs: []string{"out"}}, nodes)
	require.Error(t, err, "unmapped party")
	_, err = helium.Resolve(helium.Descriptor{Signature: cd.Signature, CircuitID: "c-0"}, itf, nodes)
	require.Error(t, err, "no evaluator")
}

func TestLocalRuntime(t *testing.T) {
	ts, err := heliumtest.NewSessions(2, 2, bgvParamsLiteral, "helper")
	require.NoError(t, err)
	params := ts.FHEParameters.(bgv.Parameters)
	encoder := bgv.NewEncoder(params)
	slots := params.MaxSlots()
	rowLen := slots / 2
	pmod := params.PlaintextModulus()

	// all inputs are the ramp vector 0, 1, 2, ...
	ramp := make([]uint64, slots)
	for i := range ramp {
		ramp[i] = uint64(i) % pmod
	}
	ip := func(helium.OperandID) *rlwe.Plaintext {
		pt := bgv.NewPlaintext(params, params.MaxLevel())
		require.NoError(t, encoder.Encode(ramp, pt))
		return pt
	}
	decode := func(op helium.Operand) []uint64 {
		pt := ts.Decryptor.DecryptNew(op.Ciphertext)
		res := make([]uint64, slots)
		require.NoError(t, encoder.Decode(pt, res))
		return res
	}

	cases := []struct {
		sig   helium.Signature
		exp   func(i int) uint64
		slots []int
	}{
		{helium.Signature{Name: "bgv-add-2"}, func(i int) uint64 { return (2 * ramp[i]) % pmod }, []int{0, 1, rowLen, slots - 1}},
		{helium.Signature{Name: "bgv-mul-2"}, func(i int) uint64 { return (ramp[i] * ramp[i]) % pmod }, []int{0, 1, rowLen, slots - 1}},
		{helium.Signature{Name: "bgv-add-n", Args: map[string]string{"n": "2"}}, func(i int) uint64 { return (2 * ramp[i]) % pmod }, []int{0, 1, rowLen, slots - 1}},
		{helium.Signature{Name: "bgv-add-all"}, func(i int) uint64 { return (2 * ramp[i]) % pmod }, []int{0, 1, rowLen, slots - 1}},
		{helium.Signature{Name: "bgv-rot-2", Args: map[string]string{"k": "3"}}, func(i int) uint64 {
			row := i / rowLen
			return (ramp[(i+3)%rowLen+row*rowLen] + ramp[(i+rowLen)%slots]) % pmod
		}, []int{0, 1, rowLen - 1, rowLen, slots - 1}},
		{helium.Signature{Name: "bgv-innersum"}, func(i int) uint64 { return (8*ramp[i] + 28) % pmod }, []int{0, 1, 2, 3}},
	}
	for _, c := range cases {
		cd := helium.Descriptor{
			Signature:   c.sig,
			CircuitID:   "test-circuit",
			NodeMapping: map[string]helium.NodeID{"p1": "node-0", "p2": "node-1"},
			Evaluator:   "helper",
		}
		tr, err := heliumtest.NewRuntime(ts, heliumtest.Circuits[c.sig.Name], cd, ip)
		require.NoError(t, err, c.sig)
		outs, err := tr.Run()
		require.NoError(t, err, c.sig)
		require.Equal(t, helium.OperandID("//helper/test-circuit/out"), outs["out"].ID)
		res := decode(outs["out"])
		for _, i := range c.slots {
			require.Equal(t, c.exp(i), res[i], "%s at slot %d", c.sig, i)
		}
	}
}
