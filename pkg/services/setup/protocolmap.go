package setup

import (
	"github.com/ldsec/helium/pkg/node"
	"github.com/ldsec/helium/pkg/protocols"
	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/ldsec/helium/pkg/utils"
)

type Description struct {
	Cpk       bool
	GaloisEls []uint64
	Rlk       bool
	Delegated bool
}

type ProtocolMap []protocols.Descriptor

func GenerateProtocolMap(setup Description, sessNodes []*node.Node, threshold int, helperNodes ...*node.Node) ProtocolMap {

	sessNodeIds := make([]pkg.NodeID, len(sessNodes))
	helperNodeIds := make([]pkg.NodeID, len(helperNodes))
	allNodeIds := make([]pkg.NodeID, 0)
	aggNodeIds := make([]pkg.NodeID, 0)
	for i, node := range sessNodes {
		sessNodeIds[i] = node.ID()
		if node.IsFullNode() {
			aggNodeIds = append(aggNodeIds, node.ID())
		}
		allNodeIds = append(allNodeIds, node.ID())
	}
	for i, node := range helperNodes {
		helperNodeIds[i] = node.ID()
		aggNodeIds = append(aggNodeIds, node.ID())
		allNodeIds = append(allNodeIds, node.ID())
	}

	nodeIDSet := utils.NewSet(sessNodeIds)

	getPartListForAgg := func(agg pkg.NodeID) []pkg.NodeID {
		partSet := nodeIDSet.Copy()
		t := threshold
		if nodeIDSet.Contains(agg) {
			t--
			partSet.Remove(agg)
		}
		part := pkg.GetRandomClientSlice(t, partSet.Elements())
		if t == threshold-1 {
			part = append(part, agg)
		}
		return part
	}

	pm := make(ProtocolMap, 0, len(setup.GaloisEls)+3)

	if threshold < len(sessNodes) {
		pm = append(pm, protocols.Descriptor{Type: protocols.SKG, Participants: sessNodeIds})
	}

	aggIndex := 0

	if setup.Cpk {
		agg := aggNodeIds[aggIndex%len(aggNodeIds)]
		aggIndex++
		part := getPartListForAgg(agg)
		pm = append(pm, protocols.Descriptor{Type: protocols.CKG, Aggregator: agg, Participants: part, Receivers: allNodeIds})
	}

	var evalKeyRec []pkg.NodeID
	if setup.Delegated {
		evalKeyRec = helperNodeIds
	} else {
		evalKeyRec = allNodeIds
	}

	if setup.Rlk {
		agg := aggNodeIds[aggIndex%len(aggNodeIds)]
		aggIndex++
		part := getPartListForAgg(agg)
		pm = append(pm, protocols.Descriptor{Type: protocols.RKG, Aggregator: agg, Participants: part, Receivers: evalKeyRec})
	}

	for i, galEl := range setup.GaloisEls {
		agg := aggNodeIds[(aggIndex+i)%len(aggNodeIds)]
		part := getPartListForAgg(agg)
		pm = append(pm, protocols.Descriptor{Type: protocols.RTG, Args: map[string]interface{}{"GalEl": galEl}, Aggregator: agg, Participants: part, Receivers: evalKeyRec})
	}

	return pm
}
