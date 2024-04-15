package protocol

import (
	"context"
	"fmt"
	"testing"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/coord"
	"github.com/ChristianMct/helium/session"
	"github.com/ChristianMct/helium/utils"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"golang.org/x/sync/errgroup"
)

func TestExecutor(t *testing.T) {

	for _, ts := range testSettings {

		if ts.T == 0 {
			ts.T = ts.N
		}

		t.Run(fmt.Sprintf("N=%d/T=%d", ts.N, ts.T), func(t *testing.T) {

			params := TestPN12QP109

			hid := helium.NodeID("helper")
			testSess, err := session.NewTestSession(ts.N, ts.T, params, hid)
			if err != nil {
				t.Fatal(err)
			}
			sessParams := testSess.SessParams
			nids := utils.NewSet(sessParams.Nodes)

			ctx := helium.NewBackgroundContext(sessParams.ID)

			executors := make(map[helium.NodeID]*Executor, len(nids))
			testTrans := NewTestTransport()
			testCoord := coord.NewTestCoordinator[Event](hid)

			ct := testSess.Encryptor.EncryptZeroNew(testSess.RlweParams.MaxLevel())
			rkg1Done := make(chan struct{})

			zeroKey := rlwe.NewSecretKey(testSess.RlweParams)

			var rkg1AggOut *AggregationOutput

			var helper *Executor
			var hip InputProvider = func(ctx context.Context, pd Descriptor) (Input, error) {
				switch pd.Signature.Type {
				case CKG, RTG, RKG1:
					p, _ := NewProtocol(pd, testSess.HelperSession)
					return p.ReadCRP()
				case RKG:
					r1Pd := pd
					r1Pd.Signature.Type = RKG1

					if rkg1AggOut != nil {
						return rkg1AggOut.Share.MHEShare, nil
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
					return rkg1AggOut.Share.MHEShare, nil
				case DEC:
					return &KeySwitchInput{OutputKey: zeroKey, InpuCt: ct}, nil
				}
				return nil, fmt.Errorf("no input for this protocol")
			}

			var pip InputProvider = func(ctx context.Context, pd Descriptor) (Input, error) {
				switch pd.Signature.Type {
				case CKG, RTG, RKG1:
					p, _ := NewProtocol(pd, testSess.HelperSession)
					return p.ReadCRP()
				case RKG:
					<-rkg1Done
					return rkg1AggOut.Share.MHEShare, nil
				case DEC:
					return &KeySwitchInput{OutputKey: zeroKey, InpuCt: ct}, nil
				}
				return nil, fmt.Errorf("no input for this protocol")
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

			evChan, _, err := testCoord.Register(helium.ContextWithNodeID(ctx, hid))
			require.Nil(t, err)
			helper, err = NewExectutor(conf, hid, testSess.HelperSession, evChan, hip)
			require.Nil(t, err)

			g, gctx := errgroup.WithContext(ctx)
			g.Go(func() error { return helper.Run(gctx, testTrans) })
			for nid := range nids {
				nid := nid
				evChan, _, err := testCoord.Register(helium.ContextWithNodeID(ctx, nid))
				require.Nil(t, err)
				nexec, err := NewExectutor(conf, nid, testSess.NodeSessions[nid], evChan, pip)
				executors[nid] = nexec
				require.Nil(t, err)
				g.Go(func() error { return nexec.Run(gctx, testTrans.TransportFor(nid)) })
				err = helper.Register(nid)
				if err != nil {
					t.Fatal(err)
				}
			}

			aggOutC := make(chan AggregationOutput, len(sigs))
			for _, sig := range sigs {
				sig := sig
				err := helper.RunSignature(ctx, sig, func(ctx context.Context, ao AggregationOutput) error {
					aggOutC <- ao
					return nil
				})
				require.Nil(t, err)
			}

			testCoord.Close()
			err = g.Wait()
			close(aggOutC)
			require.Nil(t, err)
			close(testTrans.incoming)

			for aggOut := range aggOutC {
				out := AllocateOutput(aggOut.Descriptor.Signature, testSess.RlweParams)
				err = helper.GetOutput(ctx, aggOut, out)
				require.Nil(t, err)
				checkOutput(out, aggOut.Descriptor, *testSess, t)
			}
		})

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
