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
}

// type ProtocolMap map[pkg.ProtocolID]protocols.Descriptor

// type ProtoDescrList []protocols.Descriptor

// type PresenceMap map[pkg.ProtocolID]bool

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

// type ReceiversMap map[string]utils.Set[pkg.NodeID]

// func DescriptionToReceiverSets(sd Description) ReceiversMap {
// 	rm := make(ReceiversMap)
// 	if len(sd.Cpk) > 0 {
// 		cpkReceivers := utils.NewSet(sd.Cpk)
// 		rm[protocols.Si
// 		// make(utils.Set[pkg.NodeID], len(sd.Cpk))

// 		sl = append(sl, protocols.Signature{Type: protocols.CKG})
// 	}
// 	for _, gk := range sd.GaloisKeys {
// 		if len(gk.Receivers) > 0 {
// 			sl = append(sl, protocols.Signature{Type: protocols.RTG, Args: map[string]string{"GalEl": strconv.FormatUint(gk.GaloisEl, 10)}})
// 		}
// 	}
// 	if len(sd.Rlk) > 0 {
// 		sl = append(sl, protocols.Signature{Type: protocols.RKG})
// 	}
// }

// func GenProtoMap(setup Description, nodeList pkg.NodesList, threshold int, sessNodeIds []pkg.NodeID, doThresholdSetup, assignPart bool) ProtocolMap {

// 	pm := make(ProtocolMap, len(setup.GaloisKeys)+3)

// 	nAggr := map[pkg.NodeID]int{}
// 	minAggID := func(ids []pkg.NodeID) pkg.NodeID {
// 		minID := ids[0]
// 		minVal := nAggr[minID]
// 		for _, id := range ids {
// 			if nAggr[id] < minVal {
// 				minID = id
// 				minVal = nAggr[minID]
// 			}
// 		}
// 		return minID
// 	}

// 	delegates := make(map[pkg.NodeID]pkg.NodeID)
// 	for _, n := range nodeList {
// 		switch {
// 		case n.DelegateID != "":
// 			delegates[n.NodeID] = n.DelegateID
// 		case n.NodeAddress != "":
// 			delegates[n.NodeID] = n.NodeID
// 		default:
// 			panic("either NodeAddress or DelegateID should be non-nil")
// 		}
// 	}

// 	getAggreg := func(receivers []pkg.NodeID) []pkg.NodeID {
// 		aggregs := make([]pkg.NodeID, len(receivers))
// 		for i, rec := range receivers {
// 			aggregs[i] = delegates[rec]
// 		}
// 		return aggregs
// 	}

// 	if len(setup.Cpk) > 0 {
// 		protoID := pkg.ProtocolID(protocols.CKG.ProtoID())
// 		pm[protoID] = protocols.Descriptor{ID: protoID, Signature: protocols.Signature{Type: protocols.CKG}, Aggregator: minAggID(getAggreg(setup.Cpk))}
// 	}

// 	// var galKeyCount uint64 = 0
// 	for _, key := range setup.GaloisKeys {
// 		if len(key.Receivers) == 0 {
// 			continue
// 		}
// 		protoID := pkg.ProtocolID(protocols.RTG.ProtoID(key.GaloisEl))
// 		pm[protoID] = protocols.Descriptor{
// 			ID:         protoID,
// 			Signature:  protocols.Signature{Type: protocols.RTG, Args: map[string]string{"GalEl": strconv.FormatUint(key.GaloisEl, 10)}},
// 			Aggregator: minAggID(getAggreg(key.Receivers))}
// 		// galKeyCount++
// 	}

// 	if len(setup.Rlk) > 0 {
// 		protoID := pkg.ProtocolID(protocols.RKG.ProtoID())
// 		pm[protoID] = protocols.Descriptor{ID: protoID, Signature: protocols.Signature{Type: protocols.RKG}, Aggregator: minAggID(getAggreg(setup.Rlk))}
// 	}

// 	getPartListForAgg := func(agg pkg.NodeID) []pkg.NodeID {
// 		t := threshold
// 		part := pkg.GetRandomClientSlice(t, sessNodeIds)
// 		if utils.NewSet(sessNodeIds).Contains(agg) && !utils.NewSet(part).Contains(agg) {
// 			part[0] = agg
// 		}
// 		return part
// 	}

// 	if assignPart {
// 		for id, pd := range pm {
// 			pd := pd
// 			pd.Participants = getPartListForAgg(pd.Aggregator)
// 			pm[id] = pd
// 		}
// 	}

// 	if threshold < len(sessNodeIds) && doThresholdSetup {
// 		protoID := pkg.ProtocolID(protocols.SKG.ProtoID())
// 		pm[protoID] = protocols.Descriptor{ID: protoID, Signature: protocols.Signature{Type: protocols.SKG}, Participants: sessNodeIds}
// 	}

// 	return pm
// }
