package setup

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/ldsec/helium/pkg/protocols"
	"github.com/ldsec/helium/pkg/services/compute"
	pkg "github.com/ldsec/helium/pkg/session"
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

// ComputeDescriptionToSetupDescription converts a CircuitDescription into a setup.Description by
// extractiong the keys needed for the correct circuit execution.
func ComputeDescriptionToSetupDescription(cd compute.CircuitDescription) (Description, error) {
	sd := Description{}

	// determine session nodes
	sessionNodes := make([]pkg.NodeID, 0)
	for client := range cd.InputSet {
		nopl, err := url.Parse(string(client))
		if err != nil {
			panic(fmt.Errorf("invalid operand label: %s", client))
		}
		sessionNodes = append(sessionNodes, pkg.NodeID(nopl.Host))
	}
	// log.Printf("[Convert] Session nodes are %v\n", sessionNodes)

	// determine aggregators
	aggregators := make([]pkg.NodeID, 0)
	for _, keySwitchPD := range cd.KeySwitchOps {
		aggregators = append(aggregators, pkg.NodeID(keySwitchPD.Args["aggregator"]))
	}
	// log.Printf("[Convert] Aggregators are %v\n", aggregators)

	// Collective Public Key
	sd.Cpk = sessionNodes

	// Relinearization Key
	if cd.NeedRlk {
		sd.Rlk = aggregators
	}

	// Rotation Keys
	for GaloisEl := range cd.GaloisKeys {
		keyField := struct {
			GaloisEl  uint64
			Receivers []pkg.NodeID
		}{GaloisEl, aggregators}
		sd.GaloisKeys = append(sd.GaloisKeys, keyField)
	}

	// Public Keys of output receivers
	for _, keySwitchPD := range cd.KeySwitchOps {
		// there is an external receiver
		if keySwitchPD.Type == protocols.PCKS {
			sender := pkg.NodeID(keySwitchPD.Args["target"])
			receivers := append(aggregators, sessionNodes...)
			keyField := struct {
				Sender    pkg.NodeID
				Receivers []pkg.NodeID
			}{sender, receivers}
			sd.Pk = append(sd.Pk, keyField)
		}
	}

	return sd, nil
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
		sign := protocols.Signature{Type: protocols.RKG}
		sl = append(sl, sign)

		rlkReceivers := utils.NewSet(sd.Rlk)
		rm[sign.String()] = rlkReceivers
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
