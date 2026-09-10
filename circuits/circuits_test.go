package circuits

import (
	"fmt"
	"testing"

	"github.com/ChristianMct/helium/sessions"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
)

func TestParse(t *testing.T) {
	ts, err := sessions.NewTestSession(2, 2, bgvParamsLiteral, "helper")
	require.NoError(t, err)
	params := ts.FHEParameters.(bgv.Parameters)

	rotKeys := Keys{}.Merge(Keys{GaloisEls: []uint64{params.GaloisElement(3), params.GaloisElementOrderTwoOrthogonalSubgroup()}})
	innerSumKeys := Keys{}.Merge(Keys{GaloisEls: rlwe.GaloisElementsForInnerSum(params, 1, 8)})
	expected := []struct {
		sig Signature
		itf Interface
	}{
		{Signature{Name: "bgv-add-2"}, Interface{Inputs: []Port{"//p1/in", "//p2/in"}, Outputs: []string{"out"}}},
		{Signature{Name: "bgv-mul-2"}, Interface{Inputs: []Port{"//p1/in", "//p2/in"}, Outputs: []string{"out"}, Keys: Keys{Rlk: true}}},
		{Signature{Name: "bgv-add-all"}, Interface{SumInputs: []SumPort{{Name: "sum"}}, Outputs: []string{"out"}}},
		{Signature{Name: "bgv-rot-2", Args: map[string]string{"k": "3"}}, Interface{Inputs: []Port{"//p1/in", "//p2/in"}, Outputs: []string{"out"}, Keys: rotKeys}},
		{Signature{Name: "bgv-innersum"}, Interface{Inputs: []Port{"//p1/in"}, Outputs: []string{"out"}, Keys: innerSumKeys}},
	}
	for _, c := range expected {
		itf, err := TestCircuits[c.sig.Name].Describe(c.sig, ts.FHEParameters)
		require.NoError(t, err, c.sig)
		require.Equal(t, c.itf, itf, c.sig)
	}

	// explicit interface
	itf, err := TestCircuits["bgv-add-n"].Describe(Signature{Name: "bgv-add-n", Args: map[string]string{"n": "3"}}, ts.FHEParameters)
	require.NoError(t, err)
	require.Equal(t, Interface{Inputs: []Port{"//p1/in", "//p2/in", "//p3/in"}, Outputs: []string{"out"}}, itf)

	// explicitly declared keys are merged with the inferred ones
	itf, err = Parse(func(rt Runtime) error {
		rt.Keys(Keys{GaloisEls: []uint64{5}})
		in := rt.Input("//p1/in")
		out := rt.Output("out")
		res, err := rt.Evaluator().MulRelinNew(in.Get().Ciphertext, in.Get().Ciphertext)
		out.Set(res)
		return err
	}, Signature{Name: "merged-keys"}, ts.FHEParameters)
	require.NoError(t, err)
	require.Equal(t, Keys{Rlk: true, GaloisEls: []uint64{5}}, itf.Keys)

	// placeholders track the degree and level of the ciphertexts
	var shapes []string
	shape := func(ct *rlwe.Ciphertext) { shapes = append(shapes, fmt.Sprintf("%d@%d", ct.Degree(), ct.Level())) }
	_, err = Parse(func(rt Runtime) error {
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
	}, Signature{Name: "shapes"}, ts.FHEParameters)
	require.NoError(t, err)
	maxLevel := params.MaxLevel()
	require.Equal(t, []string{
		fmt.Sprintf("1@%d", maxLevel), fmt.Sprintf("2@%d", maxLevel), fmt.Sprintf("1@%d", maxLevel), fmt.Sprintf("1@%d", maxLevel-1),
	}, shapes)

	// parsing errors
	_, err = Parse(func(rt Runtime) error { rt.Input("//p1/in"); return nil }, Signature{Name: "no-output"}, ts.FHEParameters)
	require.Error(t, err, "a circuit must declare an output")
	_, err = Parse(func(rt Runtime) error { rt.Output("out"); return fmt.Errorf("boom") }, Signature{Name: "failing"}, ts.FHEParameters)
	require.Error(t, err, "errors are reported")
	_, err = Parse(func(rt Runtime) error { rt.Input("bad"); rt.Output("out"); return nil }, Signature{Name: "bad-port"}, ts.FHEParameters)
	require.Error(t, err, "ports are validated")
	_, err = Parse(func(rt Runtime) error { rt.Output("out"); return nil }, Signature{Name: "unset-output"}, ts.FHEParameters)
	require.ErrorContains(t, err, "never set", "outputs must be set")
	_, err = Parse(func(rt Runtime) error {
		in := rt.Input("//p1/in")
		rt.Output("out").Set(in.Get().Ciphertext)
		_ = rt.Evaluator().Scheme().(*bgv.Evaluator)
		return nil
	}, Signature{Name: "scheme"}, ts.FHEParameters)
	require.ErrorContains(t, err, "scheme evaluator", "the scheme evaluator is not available")
}

func TestResolve(t *testing.T) {
	itf := Interface{Inputs: []Port{"//p1/in", "//p2/in"}, SumInputs: []SumPort{{Name: "sum"}}, Outputs: []string{"out"}}
	nodes := []sessions.NodeID{"node-0", "node-1", "node-2"}
	cd := Descriptor{
		Signature:   Signature{Name: "c"},
		CircuitID:   "c-0",
		NodeMapping: map[string]sessions.NodeID{"p1": "node-0", "p2": "node-1"},
		Evaluator:   "helper",
	}

	md, err := Resolve(cd, itf, nodes)
	require.NoError(t, err)
	require.Equal(t, map[OperandID]Port{"//node-0/c-0/in": "//p1/in", "//node-1/c-0/in": "//p2/in"}, md.Inputs)
	require.Equal(t, map[string][]OperandID{"sum": {"//node-0/c-0/sum", "//node-1/c-0/sum", "//node-2/c-0/sum"}}, md.SumInputs)
	require.Equal(t, map[string]OperandID{"out": "//helper/c-0/out"}, md.Outputs)
	require.Equal(t, nodes, md.Participants)
	require.Equal(t, []OperandID{"//node-0/c-0/in", "//node-0/c-0/sum"}, md.InputsOf["node-0"])
	require.Equal(t, []OperandID{"//node-2/c-0/sum"}, md.InputsOf["node-2"])
	require.True(t, md.IsParticipant("node-2"))
	require.False(t, md.IsParticipant("helper"))
	require.True(t, md.IsEvaluator("helper"))
	id, has := md.InputID("//p2/in")
	require.True(t, has)
	require.Equal(t, OperandID("//node-1/c-0/in"), id)
	require.Len(t, md.ExpectedInputs(), 5)

	// operand ids
	require.Equal(t, sessions.NodeID("node-1"), id.NodeID())
	require.Equal(t, sessions.CircuitID("c-0"), id.CircuitID())
	require.Equal(t, "in", id.Name())
	require.Error(t, OperandID("//node/in").Validate())

	// errors
	_, err = Resolve(cd, Interface{Inputs: []Port{"//p3/in"}, Outputs: []string{"out"}}, nodes)
	require.Error(t, err, "unmapped party")
	_, err = Resolve(Descriptor{Signature: cd.Signature, CircuitID: "c-0"}, itf, nodes)
	require.Error(t, err, "no evaluator")
}

func TestTestRuntime(t *testing.T) {
	ts, err := sessions.NewTestSession(2, 2, bgvParamsLiteral, "helper")
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
	ip := func(OperandID) *rlwe.Plaintext {
		pt := bgv.NewPlaintext(params, params.MaxLevel())
		require.NoError(t, encoder.Encode(ramp, pt))
		return pt
	}
	decode := func(op Operand) []uint64 {
		pt := ts.Decryptor.DecryptNew(op.Ciphertext)
		res := make([]uint64, slots)
		require.NoError(t, encoder.Decode(pt, res))
		return res
	}

	cases := []struct {
		sig   Signature
		exp   func(i int) uint64
		slots []int
	}{
		{Signature{Name: "bgv-add-2"}, func(i int) uint64 { return (2 * ramp[i]) % pmod }, []int{0, 1, rowLen, slots - 1}},
		{Signature{Name: "bgv-mul-2"}, func(i int) uint64 { return (ramp[i] * ramp[i]) % pmod }, []int{0, 1, rowLen, slots - 1}},
		{Signature{Name: "bgv-add-n", Args: map[string]string{"n": "2"}}, func(i int) uint64 { return (2 * ramp[i]) % pmod }, []int{0, 1, rowLen, slots - 1}},
		{Signature{Name: "bgv-add-all"}, func(i int) uint64 { return (2 * ramp[i]) % pmod }, []int{0, 1, rowLen, slots - 1}},
		{Signature{Name: "bgv-rot-2", Args: map[string]string{"k": "3"}}, func(i int) uint64 {
			row := i / rowLen
			return (ramp[(i+3)%rowLen+row*rowLen] + ramp[(i+rowLen)%slots]) % pmod
		}, []int{0, 1, rowLen - 1, rowLen, slots - 1}},
		{Signature{Name: "bgv-innersum"}, func(i int) uint64 { return (8*ramp[i] + 28) % pmod }, []int{0, 1, 2, 3}},
	}
	for _, c := range cases {
		cd := Descriptor{
			Signature:   c.sig,
			CircuitID:   "test-circuit",
			NodeMapping: map[string]sessions.NodeID{"p1": "node-0", "p2": "node-1"},
			Evaluator:   "helper",
		}
		tr, err := NewTestRuntime(ts, TestCircuits[c.sig.Name], cd, ip)
		require.NoError(t, err, c.sig)
		outs, err := tr.Run()
		require.NoError(t, err, c.sig)
		require.Equal(t, OperandID("//helper/test-circuit/out"), outs["out"].ID)
		res := decode(outs["out"])
		for _, i := range c.slots {
			require.Equal(t, c.exp(i), res[i], "%s at slot %d", c.sig, i)
		}
	}
}
