package protocols_test

import (
	"context"
	"fmt"
	"math"
	"testing"

	"github.com/ldsec/helium/pkg/node"
	"github.com/ldsec/helium/pkg/pkg"
	. "github.com/ldsec/helium/pkg/protocols"
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
	{N: 3, Helper: true},
	{N: 3, T: 2},
	{N: 3, T: 2, Helper: true},
}

var TestPN12QP109 = rlwe.ParametersLiteral{
	LogN: 12,
	Q:    []uint64{0x7ffffffec001, 0x400000008001}, // 47 + 46 bits
	P:    []uint64{0xa001},                         // 15 bits
}

func TestProtocols(t *testing.T) {

	for _, ts := range testSettings {

		te := newTestEnvironment(ts, TestPN12QP109)

		rkgPart := te.getParticipants(ts.T)
		for _, pType := range []Type{
			//SKG,
			CKG,
			RTG,
			RKG_1,
			RKG_2,
		} {

			if pType == SKG && (ts.Helper || ts.T == 0) {
				continue // Skips SKG with a helper ?
			}

			t.Run(fmt.Sprintf("Type=%s/N=%d/T=%d/Helper=%v", pType, ts.N, ts.T, ts.Helper), func(t *testing.T) {
				pd := Descriptor{Signature: Signature{Type: pType}}
				if pType == RTG {
					pd.Signature.Args = map[string]string{"GalEl": "5"}
				}
				if pType == SKG {
					pd.Participants = te.SessionNodesIds()
				} else {
					pd.Participants = te.getParticipants(ts.T)
					pd.Aggregator = te.getAggregatorID()
				}
				if pType == RKG_1 || pType == RKG_2 {
					pd.Participants = rkgPart
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
	aggShareRkg1      AggregationOutput
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
		//DoThresholdSetup: true,
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

		instances[node.ID()], err = NewProtocol(pd, sess)
		if err != nil {
			panic(err)
		}

		nodeEnv := te.envForNode(sess.NodeID)
		if pd.Signature.Type == RKG_2 {
			go func() {
				nodeEnv.incomingShares <- te.aggShareRkg1.Share
			}()
		}
		aggOutputs[node.ID()] = instances[node.ID()].Aggregate(context.Background(), nodeEnv)
	}

	for _, node := range te.Nodes {

		aggOut := <-aggOutputs[node.ID()]
		require.Nil(t, aggOut.Error)

		isAggregator := pd.Signature.Type == SKG || pd.Aggregator == node.ID()

		if !isAggregator {
			require.Nil(t, aggOut.Share.MHEShare)
		} else {

			if pd.Signature.Type == RKG_1 {
				require.NotNil(t, aggOut.Share)
				te.aggShareRkg1 = aggOut
			}

			if pd.Signature.Type != RKG_1 {

				out := <-instances[node.ID()].Output(aggOut)
				require.NoError(t, out.Error)

				nParties := len(te.SessionNodes())
				sk := te.SkIdeal
				params := te.Params
				decompositionVectorSize := params.DecompRNS(params.MaxLevelQ(), params.MaxLevelP())

				switch pd.Signature.Type {
				case SKG:
					_, isShamirShare := out.Result.(*drlwe.ShamirSecretShare)
					require.True(t, isShamirShare)
					// TODO check SKG correct
				case CKG:
					pk, isPk := out.Result.(*rlwe.PublicKey)
					require.True(t, isPk)

					require.Less(t, rlwe.NoisePublicKey(pk, sk, te.Params), math.Log2(math.Sqrt(float64(nParties))*te.Params.NoiseFreshSK())+1)
				case RTG:
					swk, isSwk := out.Result.(*rlwe.GaloisKey)
					require.True(t, isSwk)

					noise := rlwe.NoiseGaloisKey(swk, sk, params)
					noiseBound := math.Log2(math.Sqrt(float64(decompositionVectorSize))*drlwe.NoiseGaloisKey(params, nParties)) + 1
					require.Less(t, noise, noiseBound, "rtk for galEl %d should be correct", swk.GaloisElement)
				case RKG_2:
					rlk, isRlk := out.Result.(*rlwe.RelinearizationKey)
					require.True(t, isRlk)

					noiseBound := math.Log2(math.Sqrt(float64(decompositionVectorSize))*drlwe.NoiseRelinearizationKey(params, nParties)) + 1
					require.Less(t, rlwe.NoiseRelinearizationKey(rlk, sk, params), noiseBound)
				default:
					t.Fatalf("invalid protocol type")
				}
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
