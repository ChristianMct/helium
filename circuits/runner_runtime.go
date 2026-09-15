package circuits

import (
	"fmt"
	"log"

	"github.com/ChristianMct/helium"
	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"
)

// circuitRuntime is the helium.CircuitRuntime given to a circuit evaluated by the runner.
type circuitRuntime struct {
	r    *Runner
	rc   *runningCircuit
	eval helium.Evaluator
}

func (rt *circuitRuntime) Descriptor() helium.Descriptor {
	return rt.rc.cd.Clone()
}

func (rt *circuitRuntime) Parameters() helium.FHEParameters {
	return rt.r.sess.Params
}

func (rt *circuitRuntime) Keys(k helium.Keys) {
	declared := rt.rc.md.Keys
	if (k.Rlk && !declared.Rlk) || len(declared.Merge(k).GaloisEls) > len(declared.GaloisEls) {
		panic(fmt.Errorf("circuit %s requires keys %+v that are not in its interface %+v", rt.rc.cd.HID(), k, declared))
	}
}

func (rt *circuitRuntime) Input(p helium.Port) *helium.FutureOperand {
	id, has := rt.rc.md.InputID(p)
	if !has {
		panic(fmt.Errorf("input %s is not declared in the interface of circuit %s", p, rt.rc.cd.HID()))
	}
	return rt.rc.inputs[id]
}

// InputSum returns the sum of the contributions to a summed input. The contributions are
// encrypted with a common random polynomial, so that only their first components need to
// be summed.
func (rt *circuitRuntime) InputSum(name string, _ ...string) *helium.FutureOperand {
	rc := rt.rc
	sumID, has := rc.md.SumID(name)
	if !has {
		panic(fmt.Errorf("summed input %s is not declared in the interface of circuit %s", name, rc.cd.HID()))
	}

	rc.sumsMu.Lock()
	defer rc.sumsMu.Unlock()
	if fo, has := rc.sums[name]; has {
		return fo
	}

	fo := helium.NewFutureOperand(sumID)
	rc.sums[name] = fo
	go func() {
		params := rt.r.sess.Params
		rq := params.GetRLWEParameters().RingQ()

		ct := helium.NewCiphertext(params, 1)
		prng, err := sampling.NewKeyedPRNG(sumCRS(rt.r.sess, rc.cd.CircuitID, name))
		if err != nil {
			panic(err)
		}
		ring.NewUniformSampler(prng, rq).Read(ct.Value[1])

		for i, id := range rc.md.SumInputs[name] {
			c := rc.inputs[id].Get().Ciphertext
			if i == 0 {
				*ct.MetaData = *c.MetaData
			}
			rq.Add(c.Value[0], ct.Value[0], ct.Value[0])
		}
		fo.Set(ct)
	}()
	return fo
}

func (rt *circuitRuntime) Output(name string) *helium.OutputOperand {
	oo, has := rt.rc.outputs[name]
	if !has {
		panic(fmt.Errorf("output %s is not declared in the interface of circuit %s", name, rt.rc.cd.HID()))
	}
	return oo
}

func (rt *circuitRuntime) Evaluator() helium.Evaluator {
	return rt.eval
}

func (rt *circuitRuntime) Logf(msg string, v ...any) {
	log.Printf("%s | [circuits][%s] %s\n", rt.r.self, rt.rc.cd.HID(), fmt.Sprintf(msg, v...))
}
