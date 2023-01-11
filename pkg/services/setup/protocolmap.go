package setup

import (
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

type ProtocolMap []protocols.Descriptor

func GenProtoMap(setup Description, nodeList pkg.NodesList, threshold int, sessNodeIds []pkg.NodeID) ProtocolMap {

	pm := make(ProtocolMap, 0, len(setup.GaloisKeys)+3)

	if len(setup.Cpk) > 0 {
		pm = append(pm, protocols.Descriptor{Type: protocols.CKG, Receivers: setup.Cpk})
	}

	for _, key := range setup.GaloisKeys {
		if len(key.Receivers) == 0 {
			continue
		}
		pm = append(pm, protocols.Descriptor{Type: protocols.RTG, Args: map[string]interface{}{"GalEl": key.GaloisEl}, Receivers: key.Receivers})
	}

	if len(setup.Rlk) > 0 {
		pm = append(pm, protocols.Descriptor{Type: protocols.RKG, Receivers: setup.Rlk})
	}

	nAggr := map[pkg.NodeID]int{}
	minAggId := func(ids []pkg.NodeID) pkg.NodeID {
		minId := ids[0]
		minVal := nAggr[minId]
		for _, id := range ids {
			if nAggr[id] < minVal {
				minId = id
				minVal = nAggr[minId]
			}
		}
		return minId
	}

	delegates := make(map[pkg.NodeID]pkg.NodeID)
	for _, n := range nodeList {
		switch {
		case n.DelegateID != "":
			delegates[n.NodeID] = n.DelegateID
		case n.NodeAddress != "":
			delegates[n.NodeID] = n.NodeID
		default:
			panic("either NodeAddress or DelegateID should be non-nil")
		}
	}

	for i := range pm {
		pm[i].Aggregator = minAggId(pm[i].Receivers)
		nAggr[pm[i].Aggregator]++
		if del, hasDelegate := delegates[pm[i].Aggregator]; hasDelegate {
			pm[i].Aggregator = del
		}
	}

	getPartListForAgg := func(agg pkg.NodeID) []pkg.NodeID {
		t := threshold
		part := pkg.GetRandomClientSlice(t, sessNodeIds)
		if utils.NewSet(sessNodeIds).Contains(agg) && !utils.NewSet(part).Contains(agg) {
			part[0] = agg
		}
		return part
	}

	for i := range pm {
		pm[i].Participants = getPartListForAgg(pm[i].Aggregator)
	}

	if threshold < len(sessNodeIds) {
		pm = append([]protocols.Descriptor{{Type: protocols.SKG, Participants: sessNodeIds}}, pm...)
	}

	return pm
}

// func GenerateProtocolMap(setup Description, sessNodes []*node.Node, threshold int, helperNodes ...*node.Node) ProtocolMap {

// 	sessNodeIds := make([]pkg.NodeID, len(sessNodes))
// 	helperNodeIds := make([]pkg.NodeID, len(helperNodes))
// 	allNodeIds := make([]pkg.NodeID, 0)
// 	aggNodeIds := make([]pkg.NodeID, 0)
// 	for i, node := range sessNodes {
// 		sessNodeIds[i] = node.ID()
// 		if node.IsFullNode() {
// 			aggNodeIds = append(aggNodeIds, node.ID())
// 		}
// 		allNodeIds = append(allNodeIds, node.ID())
// 	}
// 	for i, node := range helperNodes {
// 		helperNodeIds[i] = node.ID()
// 		aggNodeIds = append(aggNodeIds, node.ID())
// 		allNodeIds = append(allNodeIds, node.ID())
// 	}

// 	nodeIDSet := utils.NewSet(sessNodeIds)

// 	getPartListForAgg := func(agg pkg.NodeID) []pkg.NodeID {
// 		partSet := nodeIDSet.Copy()
// 		t := threshold
// 		if nodeIDSet.Contains(agg) {
// 			t--
// 			partSet.Remove(agg)
// 		}
// 		part := pkg.GetRandomClientSlice(t, partSet.Elements())
// 		if t == threshold-1 {
// 			part = append(part, agg)
// 		}
// 		return part
// 	}

// 	pm := make(ProtocolMap, 0, len(setup.GaloisEls)+3)

// 	if threshold < len(sessNodes) {
// 		pm = append(pm, protocols.Descriptor{Type: protocols.SKG, Participants: sessNodeIds})
// 	}

// 	aggIndex := 0

// 	if len(setup.Cpk) > 0 {
// 		agg := aggNodeIds[aggIndex%len(aggNodeIds)]
// 		aggIndex++
// 		part := getPartListForAgg(agg)
// 		pm = append(pm, protocols.Descriptor{Type: protocols.CKG, Aggregator: agg, Participants: part, Receivers: allNodeIds})
// 	}

// 	var evalKeyRec []pkg.NodeID
// 	if len(setup.Delegated) {
// 		evalKeyRec = helperNodeIds
// 	} else {
// 		evalKeyRec = allNodeIds
// 	}

// 	if setup.Rlk {
// 		agg := aggNodeIds[aggIndex%len(aggNodeIds)]
// 		aggIndex++
// 		part := getPartListForAgg(agg)
// 		pm = append(pm, protocols.Descriptor{Type: protocols.RKG, Aggregator: agg, Participants: part, Receivers: evalKeyRec})
// 	}

// 	for i, galEl := range setup.GaloisEls {
// 		agg := aggNodeIds[(aggIndex+i)%len(aggNodeIds)]
// 		part := getPartListForAgg(agg)
// 		pm = append(pm, protocols.Descriptor{Type: protocols.RTG, Args: map[string]interface{}{"GalEl": galEl}, Aggregator: agg, Participants: part, Receivers: evalKeyRec})
// 	}

// 	return pm
// }
