package protocols

import (
	"context"
	"fmt"
	"testing"

	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
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

		ct := testSess.Encryptor.EncryptZeroNew(testSess.RlweParams.MaxLevel())
		rkg1Done := make(chan struct{})
		var rkg1AggOut *AggregationOutput

		var helper *Executor
		var hip InputProvider = func(ctx context.Context, pd Descriptor) (Input, error) {
			switch pd.Signature.Type {
			case RKG:
				r1Pd := pd
				r1Pd.Signature.Type = RKG_1

				if rkg1AggOut != nil {
					return rkg1AggOut.Share, nil
				}

				aggOutC := make(chan AggregationOutput, 1) // TODO the next command is blocking, see if we want to make it async
				err = helper.RunDescriptorAsAggregator(ctx, r1Pd, func(ctx context.Context, ao AggregationOutput) error {
					aggOutC <- ao
					return nil
				})
				if err != nil {
					return nil, err
				}
				rkg1AggOutv := <-aggOutC
				rkg1AggOut = &rkg1AggOutv
				if rkg1AggOut.Error != nil {
					return nil, rkg1AggOut.Error
				}
				close(rkg1Done)
				return rkg1AggOut.Share, nil
			case DEC:
				return ct, nil
			}
			return nil, nil
		}

		var pip InputProvider = func(ctx context.Context, pd Descriptor) (Input, error) {
			switch pd.Signature.Type {
			case RKG:
				<-rkg1Done
				return rkg1AggOut.Share, nil
			case DEC:
				return ct, nil
			}
			return nil, nil
		}

		sigs := []Signature{
			{Type: CKG},
			{Type: RTG, Args: map[string]string{"GalEl": "5"}},
			{Type: RTG, Args: map[string]string{"GalEl": "25"}},
			{Type: RKG},
			{Type: DEC, Args: map[string]string{"target": "node-0", "smudging": "40"}},
		}

		conf := ExecutorConfig{
			SigQueueSize:     len(sigs),
			MaxProtoPerNode:  1,
			MaxAggregation:   1,
			MaxParticipation: 1,
		}

		helper, err = NewExectutor(conf, hid, testSess.HelperSession, testCoord, hip, testTrans)
		require.Nil(t, err)

		g, gctx := errgroup.WithContext(ctx)
		g.Go(func() error { return helper.Run(gctx) })
		for nid := range nids {
			nid := nid
			executors[nid], err = NewExectutor(conf, nid, testSess.NodeSessions[nid], testCoord.NewNodeCoordinator(nid), pip, testTrans.TransportFor(nid))
			require.Nil(t, err)
			g.Go(func() error { return executors[nid].Run(gctx) })
			err = helper.Register(nid)
			if err != nil {
				t.Fatal(err)
			}
		}

		for _, sig := range sigs {
			t.Run(fmt.Sprintf("N=%d/T=%d/Sig=%s", ts.N, ts.T, sig), func(t *testing.T) {
				sig := sig
				aggOutC := make(chan AggregationOutput)
				err := helper.RunSignature(ctx, sig, func(ctx context.Context, ao AggregationOutput) error {
					aggOutC <- ao
					return nil
				})
				require.Nil(t, err)
				aggOut := <-aggOutC
				out := helper.GetOutput(ctx, aggOut)
				checkOutput(out, aggOut.Descriptor, *testSess, t)
			})
		}
		close(testCoord.incoming)
		close(testTrans.incoming)

		err = g.Wait()
		require.Nil(t, err)

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
