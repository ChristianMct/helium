package setup

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strconv"
	"testing"

	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/protocols"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v4/drlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe"

	//"github.com/ldsec/helium/pkg/services/compute"
	"github.com/ldsec/helium/pkg/utils"
)

type Description struct {
	Cpk        []pkg.NodeID
	GaloisKeys []struct {
		GaloisEl  uint64
		Receivers []pkg.NodeID
	}
	Rlk []pkg.NodeID
	Pk  []struct {
		Sender    pkg.NodeID
		Receivers []pkg.NodeID
	}
}

func MergeSetupDescriptions(sd1, sd2 Description) (sdOut Description) {
	sdOut.Cpk = mergeReceivers(sd1.Cpk, sd2.Cpk)
	sdOut.Rlk = mergeReceivers(sd1.Rlk, sd2.Rlk)
	gkr := make(map[uint64][]pkg.NodeID)
	for _, gkr1 := range sd1.GaloisKeys {
		gkr[gkr1.GaloisEl] = gkr1.Receivers
	}
	for _, gkr2 := range sd2.GaloisKeys {
		gkr1 := gkr[gkr2.GaloisEl]
		gkr[gkr2.GaloisEl] = mergeReceivers(gkr1, gkr2.Receivers)
	}
	if len(gkr) != 0 {
		sdOut.GaloisKeys = make([]struct {
			GaloisEl  uint64
			Receivers []pkg.NodeID
		}, 0, len(gkr))
	}
	for gke, gkr := range gkr {
		sdOut.GaloisKeys = append(sdOut.GaloisKeys, struct {
			GaloisEl  uint64
			Receivers []pkg.NodeID
		}{GaloisEl: gke, Receivers: gkr})
	}
	return sdOut
}

func mergeReceivers(r1, r2 []pkg.NodeID) (rOut []pkg.NodeID) {
	s1 := utils.NewSet(r1)
	s1.AddAll(utils.NewSet(r2))
	els := s1.Elements()
	if len(els) == 0 {
		return nil
	}
	elsString := make([]string, len(els))
	for i, el := range els {
		elsString[i] = string(el)
	}
	sort.Strings(elsString)
	for i, el := range elsString {
		els[i] = pkg.NodeID(el)
	}
	return els
}

type SignatureList []protocols.Signature
type ReceiversMap map[string]utils.Set[pkg.NodeID]

func DescriptionToSignatureList(sd Description) (SignatureList, ReceiversMap) {
	sl := make(SignatureList, 0, 3+len(sd.GaloisKeys))
	rm := make(ReceiversMap)
	if len(sd.Cpk) > 0 {
		sign := protocols.Signature{Type: protocols.CKG}
		sl = append(sl, sign)

		cpkReceivers := utils.NewSet(sd.Cpk)
		rm[sign.String()] = cpkReceivers
	}
	for _, gk := range sd.GaloisKeys {
		if len(gk.Receivers) > 0 {
			sign := protocols.Signature{Type: protocols.RTG, Args: map[string]string{"GalEl": strconv.FormatUint(gk.GaloisEl, 10)}}
			sl = append(sl, sign)

			rtkReceivers := utils.NewSet(gk.Receivers)
			rm[sign.String()] = rtkReceivers
		}

	}
	if len(sd.Rlk) > 0 {
		sl = append(sl, protocols.Signature{Type: protocols.RKG})

		rlkReceivers := utils.NewSet(sd.Rlk)
		rm[protocols.Signature{Type: protocols.RKG}.String()] = rlkReceivers
	}
	for _, pk := range sd.Pk {
		if len(pk.Receivers) > 0 {
			sign := protocols.Signature{Type: protocols.PK, Args: map[string]string{"Sender": string(pk.Sender)}}
			sl = append(sl, sign)

			pkReceivers := utils.NewSet(pk.Receivers)
			rm[sign.String()] = pkReceivers
		}
	}

	return sl, rm
}

func (sl SignatureList) Contains(other protocols.Signature) bool {
	for _, sig := range sl {
		if sig.Equals(other) {
			return true
		}
	}
	return false
}

func (sd Description) String() string {
	return fmt.Sprintf(`
	{
		Cpk: %v,
		GaloisKeys: %v,
		Rlk: %v,
		Pk: %v
	}`, sd.Cpk, sd.GaloisKeys, sd.Rlk, sd.Pk)
}

// Based on the session information, check if the protocol was performed correctly.
func CheckTestSetup(ctx context.Context, t *testing.T, nid pkg.NodeID, lt *pkg.TestSession, setup Description, n pkg.PublicKeyBackend) {

	params := lt.RlweParams
	sk := lt.SkIdeal
	nParties := len(lt.HelperSession.Nodes)

	// check CPK
	if utils.NewSet(setup.Cpk).Contains(nid) {
		cpk, err := n.GetCollectivePublicKey(ctx)
		if err != nil {
			t.Fatalf("%s | %s", nid, err)
		}

		require.Less(t, rlwe.NoisePublicKey(cpk, sk, params.Parameters), math.Log2(math.Sqrt(float64(nParties))*params.NoiseFreshSK())+1)
	}

	// check RTG
	for _, key := range setup.GaloisKeys {
		if utils.NewSet(key.Receivers).Contains(nid) {
			rtk, err := n.GetGaloisKey(ctx, key.GaloisEl)
			if err != nil {
				t.Fatalf("%s | %s", nid, err)
			}

			decompositionVectorSize := params.DecompRNS(params.MaxLevelQ(), params.MaxLevelP())
			noiseBound := math.Log2(math.Sqrt(float64(decompositionVectorSize))*drlwe.NoiseGaloisKey(params.Parameters, nParties)) + 1
			require.Less(t, rlwe.NoiseGaloisKey(rtk, sk, params.Parameters), noiseBound, "rtk for galEl %d should be correct", key.GaloisEl)
		}
	}

	// check RLK
	if utils.NewSet(setup.Rlk).Contains(nid) {
		rlk, err := n.GetRelinearizationKey(ctx)
		if err != nil {
			t.Fatalf("%s | %s", nid, err)
		}

		BaseRNSDecompositionVectorSize := params.DecompRNS(params.MaxLevelQ(), params.MaxLevelP())
		noiseBound := math.Log2(math.Sqrt(float64(BaseRNSDecompositionVectorSize))*drlwe.NoiseRelinearizationKey(params.Parameters, nParties)) + 1

		require.Less(t, rlwe.NoiseRelinearizationKey(rlk, sk, params.Parameters), noiseBound)
	}
}
