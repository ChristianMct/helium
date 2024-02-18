package protocols

import (
	"context"
	"fmt"
	"testing"

	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/stretchr/testify/require"
)

func TestExecutor(t *testing.T) {

	for _, ts := range testSettings {

		if ts.T == 0 {
			ts.T = ts.N
		}

		params := TestPN12QP109

		hid := pkg.NodeID("helper")
		testSess, err := pkg.NewTestSession(ts.N, ts.T, params, hid)
		if err != nil {
			t.Fatal(err)
		}
		sessParams := testSess.SessParams
		nids := utils.NewSet(sessParams.Nodes)

		ctx := pkg.NewContext(&sessParams.ID, nil)

		executors := make(map[pkg.NodeID]*Executor, len(nids))
		testTrans := NewTestTransport()
		testCoord := NewTestCoordinator()
		testAggBackend := NewTestAggregationOutputBackend()

		ct := testSess.Encryptor.EncryptZeroNew(testSess.RlweParams.MaxLevel())

		var helper *Executor
		var hip InputProvider = func(ctx context.Context, pd Descriptor) (Input, error) {
			switch pd.Signature.Type {
			case RKG:
				r1Pd := pd
				r1Pd.Signature.Type = RKG_1

				rkg1AggOutp, err := testAggBackend.Get(ctx, r1Pd)
				if err == nil {
					return rkg1AggOutp.Share, nil
				}

				aggOutC, err := helper.RunDescriptorAsAggregator(ctx, r1Pd)
				if err != nil {
					return nil, err
				}
				rkg1AggOut := <-aggOutC
				if rkg1AggOut.Error != nil {
					return nil, rkg1AggOut.Error
				}
				return rkg1AggOut.Share, nil
			case DEC:
				return ct, nil
			}
			return nil, nil
		}

		var pip InputProvider = func(ctx context.Context, pd Descriptor) (Input, error) {
			switch pd.Signature.Type {
			case RKG:
				r1pd := pd
				r1pd.Signature.Type = RKG_1
				rkg1AggOut, err := testAggBackend.Get(ctx, r1pd)
				if err != nil {
					return nil, err
				}
				return rkg1AggOut.Share, nil
			case DEC:
				return ct, nil
			}
			return nil, nil
		}

		helper, err = NewExectutor(hid, testSess.HelperSession, testCoord, hip, testAggBackend, testTrans)
		require.Nil(t, err)
		go helper.RunService(ctx)
		for nid := range nids {
			executors[nid], err = NewExectutor(nid, testSess.NodeSessions[nid], testCoord.NewNodeCoordinator(nid), pip, nil, testTrans.TransportFor(nid))
			require.Nil(t, err)
			go executors[nid].RunService(ctx)
			err = helper.Register(nid)
			if err != nil {
				t.Fatal(err)
			}
		}

		sigs := []Signature{
			{Type: CKG},
			{Type: RTG, Args: map[string]string{"GalEl": "5"}},
			{Type: RTG, Args: map[string]string{"GalEl": "25"}},
			{Type: RKG},
			{Type: DEC, Args: map[string]string{"target": "node-0", "smudging": "40"}},
		}

		for _, sig := range sigs {
			t.Run(fmt.Sprintf("N=%d/T=%d/Sig=%s", ts.N, ts.T, sig), func(t *testing.T) {
				aggOutC, err := helper.RunSignatureAsAggregator(ctx, sig)
				require.Nil(t, err)
				aggOut := <-aggOutC
				out := helper.GetOutput(ctx, aggOut)
				checkOutput(out, aggOut.Descriptor, *testSess, t)
			})
		}
	}
}

type TestAggregationOutputBackend struct {
	bk map[string]*AggregationOutput
}

func NewTestAggregationOutputBackend() *TestAggregationOutputBackend {
	return &TestAggregationOutputBackend{
		bk: make(map[string]*AggregationOutput),
	}
}

func (agbk *TestAggregationOutputBackend) Put(ctx context.Context, aggOut AggregationOutput) error {
	pid := string(aggOut.Descriptor.ID())
	if _, has := agbk.bk[pid]; has {
		return fmt.Errorf("backend already has aggregation output for %s", pid)
	}
	agbk.bk[pid] = &aggOut
	return nil
}

func (agbk *TestAggregationOutputBackend) Get(ctx context.Context, pd Descriptor) (*AggregationOutput, error) {
	pid := string(pd.ID())
	if aggOut, has := agbk.bk[pid]; has {
		return aggOut, nil
	}
	return nil, fmt.Errorf("backend has no aggregation output for %s", pid)
}
