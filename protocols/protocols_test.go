package protocols

import (
	"fmt"
	"math"
	"slices"
	"testing"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/session"
	"github.com/ChristianMct/helium/utils"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	drlwe "github.com/tuneinsight/lattigo/v5/mhe"
	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
)

type testSetting struct {
	N      int // N - total parties
	T      int // T - parties in the access structure
	Helper bool
}

var testSettings = []testSetting{
	{N: 3},
	{N: 3, T: 2},
}

var TestPN12QP109 = bgv.ParametersLiteral{
	LogN:             12,
	Q:                []uint64{0x7ffffffec001, 0x400000008001}, // 47 + 46 bits
	P:                []uint64{0xa001},                         // 15 bits
	PlaintextModulus: 65537,
}

func TestProtocols(t *testing.T) {

	for _, ts := range testSettings {

		if ts.T == 0 {
			ts.T = ts.N
		}

		params := TestPN12QP109

		hid := helium.NodeID("helper")
		testSess, err := session.NewTestSession(ts.N, ts.T, params, hid)
		if err != nil {
			t.Fatal(err)
		}
		sessParams := testSess.SessParams
		nids := utils.NewSet(sessParams.Nodes)

		encryptor := rlwe.NewEncryptor(testSess.RlweParams, testSess.SkIdeal)

		ct := encryptor.EncryptZeroNew(testSess.RlweParams.MaxLevel())

		sigs := []Signature{
			{Type: CKG},
			{Type: RTG, Args: map[string]string{"GalEl": "5"}},
			{Type: RKG},
			{Type: DEC, Args: map[string]string{"target": "node-0", "smudging": "40"}},
		}

		zeroKey := rlwe.NewSecretKey(testSess.RlweParams)

		for _, sig := range sigs {
			parts, err := GetParticipants(sig, nids, ts.T)
			if err != nil {
				t.Fatal(err)
			}
			pd := Descriptor{Signature: sig, Participants: parts, Aggregator: hid}
			t.Run(fmt.Sprintf("N=%d/T=%d/Type=%s", ts.N, ts.T, pd.Signature.Type), func(t *testing.T) {
				var input Input

				p, err := NewProtocol(pd, testSess.HelperSession)
				if err != nil {
					t.Fatal(err)
				}

				switch pd.Signature.Type {
				case CKG, RTG:
					input, err = p.ReadCRP()
					require.Nil(t, err)
				case RKG:
					input, err = p.ReadCRP()
					require.Nil(t, err)
					aggOutR1 := runProto(Descriptor{Signature: Signature{Type: RKG1}, Participants: pd.Participants, Aggregator: pd.Aggregator}, *testSess, input, t)
					if aggOutR1.Error != nil {
						t.Fatal(aggOutR1.Error)
					}
					input = aggOutR1.Share.MHEShare
				case DEC:
					input = &KeySwitchInput{OutputKey: zeroKey, InpuCt: ct}
				default:
					t.Fatal("unknown protocol type")
				}
				aggOut := runProto(pd, *testSess, input, t)

				out := AllocateOutput(pd.Signature, testSess.RlweParams)
				err = p.Output(input, aggOut, out)
				require.Nil(t, err)
				checkOutput(out, pd, *testSess, t)
			})
		}
	}
}

func runProto(pd Descriptor, testSess session.TestSession, input Input, t *testing.T) AggregationOutput {

	helperP, err := NewProtocol(pd, testSess.HelperSession)
	if err != nil {
		t.Fatal(err)
	}

	ctx := helium.NewBackgroundContext(testSess.SessParams.ID)
	incoming := make(chan Share)
	resc := make(chan AggregationOutput, 1)
	errc := make(chan error, 1)
	go func() {
		aggOutC := helperP.Aggregate(ctx, incoming)
		resc <- <-aggOutC
	}()

	for nid, nodeSess := range testSess.NodeSessions {
		nodeP, err := NewProtocol(pd, nodeSess)

		if err != nil {
			t.Fatal(err)
		}

		ski, err := nodeSess.GetSecretKeyForGroup(pd.Participants)
		require.Nil(t, err)

		share := nodeP.AllocateShare()
		err = nodeP.GenShare(ski, input, &share)

		if !slices.Contains(pd.Participants, nid) {
			require.NotNil(t, err, "non participants should not generate a share")
			continue
		}

		if pd.Signature.Type == DEC && helium.NodeID(pd.Signature.Args["target"]) == nid {
			require.NotNil(t, err, "decryption receiver should not generate a share")
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			incoming <- share
		}()

	}

	var aggOut AggregationOutput
	select {
	case err := <-errc:
		t.Fatal(fmt.Errorf("aggregator returned error instead of aggregating:%s", err))
	case aggOut = <-resc:
		if aggOut.Error != nil {
			t.Fatal(fmt.Errorf("aggregator returned aggregation error: %s", aggOut.Error))
		}
		if aggOut.Share.MHEShare == nil {
			t.Fatal("aggregator returned a nil share without error")
		}
	}

	return aggOut
}

func checkOutput(out interface{}, pd Descriptor, testSess session.TestSession, t *testing.T) {

	nParties := len(testSess.NodeSessions)
	sk := testSess.SkIdeal
	params := testSess.RlweParams
	decompositionVectorSize := params.BaseRNSDecompositionVectorSize(params.MaxLevelQ(), params.MaxLevelP())

	switch pd.Signature.Type {
	case CKG:
		pk, isPk := out.(*rlwe.PublicKey)
		require.True(t, isPk)
		require.Less(t, rlwe.NoisePublicKey(pk, sk, params), math.Log2(math.Sqrt(float64(nParties))*params.NoiseFreshSK())+1)
	case RTG:
		swk, isSwk := out.(*rlwe.GaloisKey)
		require.True(t, isSwk)

		noise := rlwe.NoiseGaloisKey(swk, sk, params)
		noiseBound := math.Log2(math.Sqrt(float64(decompositionVectorSize))*drlwe.NoiseGaloisKey(params, nParties)) + 1
		require.Less(t, noise, noiseBound, "rtk for galEl %d should be correct", swk.GaloisElement)
	case RKG:
		rlk, isRlk := out.(*rlwe.RelinearizationKey)
		require.True(t, isRlk)

		noiseBound := math.Log2(math.Sqrt(float64(decompositionVectorSize))*drlwe.NoiseRelinearizationKey(params, nParties)) + 1
		require.Less(t, rlwe.NoiseRelinearizationKey(rlk, sk, params), noiseBound)
	case DEC:
		recSk, err := testSess.NodeSessions[helium.NodeID("node-0")].GetSecretKeyForGroup(pd.Participants)
		if err != nil {
			t.Fatal(err)
		}
		dec := rlwe.NewDecryptor(testSess.RlweParams, recSk)

		ct, isCt := out.(*rlwe.Ciphertext)
		require.True(t, isCt)
		std, _, _ := rlwe.Norm(ct, dec)
		require.Less(t, std, testSess.RlweParams.NoiseFreshPK()) // TODO better bound
	default:
		t.Fatalf("invalid protocol type")
	}
}
