package setup

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/protocols"

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

// // CircuitToSetupDescription converts a CircuitDescription into a setup.Description by
// // extractiong the keys needed for the correct circuit execution.
// func CircuitToSetupDescription(c compute.Circuit, params bgv.Parameters) (Description, error) {
// 	sd := Description{}

// 	cd, err := compute.ParseCircuit(c, "dummy-cid", params, nil)
// 	if err != nil {
// 		return Description{}, err
// 	}

// 	// determine session nodes
// 	sessionNodes := make([]pkg.NodeID, 0)
// 	for client := range cd.InputSet {
// 		nopl, err := url.Parse(string(client))
// 		if err != nil {
// 			panic(fmt.Errorf("invalid operand label: %s", client))
// 		}
// 		sessionNodes = append(sessionNodes, pkg.NodeID(nopl.Host))
// 	}
// 	// log.Printf("[Convert] Session nodes are %v\n", sessionNodes)

// 	// determine aggregators
// 	aggregators := make([]pkg.NodeID, 0)
// 	for _, ksSig := range cd.KeySwitchOps {
// 		aggregators = append(aggregators, pkg.NodeID(ksSig.Args["aggregator"]))
// 	}
// 	// log.Printf("[Convert] Aggregators are %v\n", aggregators)

// 	// Collective Public Key
// 	sd.Cpk = sessionNodes

// 	// Relinearization Key
// 	if cd.NeedRlk {
// 		sd.Rlk = aggregators
// 	}

// 	// Rotation Keys
// 	for GaloisEl := range cd.GaloisKeys {
// 		keyField := struct {
// 			GaloisEl  uint64
// 			Receivers []pkg.NodeID
// 		}{GaloisEl, aggregators}
// 		sd.GaloisKeys = append(sd.GaloisKeys, keyField)
// 	}

// 	// Public Keys of output receivers
// 	for _, ksSig := range cd.KeySwitchOps {
// 		// there is an external receiver
// 		if ksSig.Type == protocols.PCKS {
// 			sender := pkg.NodeID(ksSig.Args["target"])
// 			receivers := append(aggregators, sessionNodes...)
// 			keyField := struct {
// 				Sender    pkg.NodeID
// 				Receivers []pkg.NodeID
// 			}{sender, receivers}
// 			sd.Pk = append(sd.Pk, keyField)
// 		}
// 	}

// 	return sd, nil
// }

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
