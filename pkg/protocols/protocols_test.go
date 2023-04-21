package protocols_test

import (
	"context"
	"fmt"
	"math"
	"math/bits"
	"testing"

	"github.com/ldsec/helium/pkg/node"
	. "github.com/ldsec/helium/pkg/protocols"
	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v4/drlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

type testSetting struct {
	N      int // N - total parties
	T      int // T - parties in the access structure
	Helper bool
}

var testSettings = []testSetting{
	{N: 2},
	{N: 3},
	{N: 3, T: 2},
	{N: 3, Helper: true},
	{N: 3, T: 2, Helper: true},
}

func TestProtocols(t *testing.T) {
	for _, ts := range testSettings {
		for _, pType := range []Type{
			SKG,
			CKG,
			RTG,
			RKG,
		} {

			if pType == SKG && (ts.Helper || ts.T == 0) {
				continue // Skips SKG with a helper ?
			}

			t.Run(fmt.Sprintf("Type=%s/N=%d/T=%d/Helper=%v", pType, ts.N, ts.T, ts.Helper), func(t *testing.T) {
				te := newTestEnvironment(ts, rlwe.TestPN12QP109)
				pd := Descriptor{Type: pType}
				if pType == RTG {
					pd.Args = map[string]interface{}{"GalEl": uint64(5)}
				}
				if pType == SKG {
					pd.Participants = te.SessionNodesIds()
				} else {
					pd.Participants = te.getParticipants(ts.T)
					pd.Aggregator = te.getAggregatorID()
				}
				te.runAndCheck(pd, t)
			})
		}
	}
}

type testEnvironment struct {
	N, T int
	*node.LocalTest
	allOutgoingShares chan Share
	incShareForParty  map[pkg.NodeID]chan Share
}

func newTestEnvironment(ts testSetting, params rlwe.ParametersLiteral) *testEnvironment {
	te := new(testEnvironment)
	te.N = ts.N
	if ts.T == 0 {
		te.T = ts.N
	} else {
		te.T = ts.T
	}
	tc := node.LocalTestConfig{
		FullNodes: ts.N,
		Session: &pkg.SessionParameters{
			RLWEParams: params,
			T:          ts.T,
		},
		DoThresholdSetup: true,
	}
	if ts.Helper {
		tc.HelperNodes = 1
	}
	te.LocalTest = node.NewLocalTest(tc)
	te.allOutgoingShares = make(chan Share)
	te.incShareForParty = make(map[pkg.NodeID]chan Share)
	for _, node := range te.LocalTest.Nodes {
		te.incShareForParty[node.ID()] = make(chan Share)
	}

	go func() {
		for os := range te.allOutgoingShares {
			for _, id := range os.To {
				insh, exists := te.incShareForParty[id]
				if !exists {
					panic(fmt.Errorf("invalid outgoing share: %v", os))
				}
				insh <- os
			}
		}
	}()

	return te
}

func (te *testEnvironment) runAndCheck(pd Descriptor, t *testing.T) {
	aggOutputs := make(map[pkg.NodeID]chan AggregationOutput)
	instances := make(map[pkg.NodeID]Instance)
	var err error
	for _, node := range te.LocalTest.Nodes {
		sess, _ := node.GetSessionFromID("test-session")
		instances[node.ID()], err = NewProtocol(pd, sess, pkg.ProtocolID(pd.Type.String()))
		if err != nil {
			t.Fatal(err)
		}
		aggOutputs[node.ID()] = instances[node.ID()].Aggregate(context.Background(), sess, te.envForNode(sess.NodeID))
	}

	for _, node := range te.Nodes {

		aggOut := <-aggOutputs[node.ID()]
		require.Nil(t, aggOut.Error)

		isAggregator := pd.Type == SKG || pd.Aggregator == node.ID()

		if !isAggregator {
			require.Nil(t, aggOut.Round)
		} else {

			out := <-instances[node.ID()].Output(aggOut)

			if pd.Type != SKG || te.T != te.N {
				require.NotNil(t, out.Result)
			}

			switch pd.Type {
			case SKG:
				_, isShamirShare := out.Result.(*drlwe.ShamirSecretShare)
				require.True(t, isShamirShare)
				// TODO check SKG correct
			case CKG:
				pk, isPk := out.Result.(*rlwe.PublicKey)
				require.True(t, isPk)
				log2BoundPk := bits.Len64(uint64(len(te.SessionNodes())) * te.Params.NoiseBound() * uint64(te.Params.N()))
				require.True(t, rlwe.PublicKeyIsCorrect(pk, te.SkIdeal, te.Params, log2BoundPk))
			case RTG:
				swk, isSwk := out.Result.(*rlwe.SwitchingKey)
				require.True(t, isSwk)
				log2BoundRtk := bits.Len64(uint64(
					te.Params.N() * len(swk.Value) * len(swk.Value[0]) *
						(te.Params.N()*3*int(math.Floor(rlwe.DefaultSigma*6)) +
							2*3*int(math.Floor(rlwe.DefaultSigma*6)) + te.Params.N()*3)))
				require.True(t, rlwe.RotationKeyIsCorrect(swk, pd.Args["GalEl"].(uint64), te.SkIdeal, te.Params, log2BoundRtk), "rtk for galEl %d should be correct", pd.Args["GaloisEl"])
			case RKG:
				rlk, isRlk := out.Result.(*rlwe.RelinearizationKey)
				require.True(t, isRlk)
				levelQ, levelP := te.Params.QCount()-1, te.Params.PCount()-1
				decompSize := te.Params.DecompPw2(levelQ, levelP) * te.Params.DecompRNS(levelQ, levelP)
				log2BoundRlk := bits.Len64(uint64(
					te.Params.N() * decompSize * (te.Params.N()*3*int(te.Params.NoiseBound()) +
						2*3*int(te.Params.NoiseBound()) + te.Params.N()*3)))

				require.True(t, rlwe.RelinearizationKeyIsCorrect(rlk.Keys[0], te.SkIdeal, te.Params, log2BoundRlk))
			default:
				t.Fatalf("invalid protocol type")
			}
		}
	}

}

func (te *testEnvironment) getAggregatorID() pkg.NodeID {
	if len(te.HelperNodes) > 0 {
		return te.HelperNodes[0].ID()
	}
	return te.Nodes[0].ID()
}

func (te *testEnvironment) getParticipants(t int) []pkg.NodeID {
	if t == 0 || t > len(te.SessionNodes()) {
		t = len(te.SessionNodes())
	}
	return pkg.GetRandomClientSlice(t, te.SessionNodesIds())
}

func (te *testEnvironment) envForNode(nid pkg.NodeID) *testNodeEnvironment {
	return &testNodeEnvironment{
		outgoingShares: te.allOutgoingShares,
		incomingShares: te.incShareForParty[nid],
	}
}

type testNodeEnvironment struct {
	incomingShares       chan Share
	incomingShareQueries chan ShareQuery
	outgoingShares       chan Share
	outgoingShareQueries chan ShareQuery
}

func (te *testNodeEnvironment) ShareQuery(sq ShareQuery) {
	te.outgoingShareQueries <- sq
}

func (te *testNodeEnvironment) OutgoingShares() chan<- Share {
	return te.outgoingShares
}

func (te *testNodeEnvironment) IncomingShares() <-chan Share {
	return te.incomingShares
}

func (te *testNodeEnvironment) IncomingShareQueries() <-chan ShareQuery {
	return te.incomingShareQueries
}
