package setup

import (
	"strconv"

	"github.com/ldsec/helium/pkg/protocols"
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
