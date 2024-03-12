package centralized

import (
	"fmt"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/circuits"
	"github.com/ldsec/helium/pkg/coordinator"
	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/protocols"
	"github.com/ldsec/helium/pkg/utils"
)

func getApiEvent(event coordinator.Event) *api.Event {
	apiEvent := &api.Event{}
	if event.CircuitEvent != nil {
		apiEvent.CircuitEvent = &api.CircuitEvent{
			Type:        api.EventType(event.CircuitEvent.EventType),
			Descriptor_: getAPICircuitDesc(event.CircuitEvent.Descriptor),
		}
	}
	if event.ProtocolEvent != nil {
		apiDesc := getAPIProtocolDesc(&event.ProtocolEvent.Descriptor)
		apiEvent.ProtocolEvent = &api.ProtocolEvent{Type: api.EventType(event.ProtocolEvent.EventType), Descriptor_: apiDesc}
	}
	return apiEvent
}

func getEventFromAPI(apiEvent *api.Event) coordinator.Event {
	event := coordinator.Event{}
	if apiEvent.CircuitEvent != nil {
		event.CircuitEvent = &circuits.Event{
			EventType:  circuits.EventType(apiEvent.CircuitEvent.Type),
			Descriptor: *getCircuitDescFromAPI(apiEvent.CircuitEvent.Descriptor_),
		}
	}
	if apiEvent.ProtocolEvent != nil {
		event.ProtocolEvent = &protocols.Event{
			EventType:  protocols.EventType(apiEvent.ProtocolEvent.Type),
			Descriptor: *getProtocolDescFromAPI(apiEvent.ProtocolEvent.Descriptor_),
		}
	}
	return event
}

func getAPIProtocolDesc(pd *protocols.Descriptor) *api.ProtocolDescriptor {
	apiDesc := &api.ProtocolDescriptor{
		ProtocolType: api.ProtocolType(pd.Signature.Type),
		Args:         make(map[string]string, len(pd.Signature.Args)),
		Aggregator:   &api.NodeID{NodeId: string(pd.Aggregator)},
		Participants: make([]*api.NodeID, 0, len(pd.Participants)),
	}
	for k, v := range pd.Signature.Args {
		apiDesc.Args[k] = v
	}
	for _, p := range pd.Participants {
		apiDesc.Participants = append(apiDesc.Participants, &api.NodeID{NodeId: string(p)})
	}
	return apiDesc
}

func getProtocolDescFromAPI(apiPD *api.ProtocolDescriptor) *protocols.Descriptor {
	desc := &protocols.Descriptor{
		Signature:    protocols.Signature{Type: protocols.Type(apiPD.ProtocolType), Args: make(map[string]string)},
		Aggregator:   pkg.NodeID(apiPD.Aggregator.NodeId),
		Participants: make([]pkg.NodeID, 0, len(apiPD.Participants)),
	}
	for k, v := range apiPD.Args {
		desc.Signature.Args[k] = v
	}
	for _, p := range apiPD.Participants {
		desc.Participants = append(desc.Participants, pkg.NodeID(p.NodeId))
	}
	return desc
}

func getAPICircuitDesc(cd circuits.Descriptor) *api.CircuitDescriptor {
	apiDesc := &api.CircuitDescriptor{
		CircuitSignature: &api.CircuitSignature{
			Name: string(cd.Name),
			Args: make(map[string]string, len(cd.Args)),
		},
		CircuitID:   &api.CircuitID{CircuitID: string(cd.ID)},
		NodeMapping: make(map[string]*api.NodeID, len(cd.NodeMapping)),
		Evaluator:   &api.NodeID{NodeId: string(cd.Evaluator)},
	}

	for k, v := range cd.Args {
		apiDesc.CircuitSignature.Args[k] = v
	}

	for s, nid := range cd.NodeMapping {
		apiDesc.NodeMapping[s] = &api.NodeID{NodeId: string(nid)}
	}

	return apiDesc
}

func getCircuitDescFromAPI(apiCd *api.CircuitDescriptor) *circuits.Descriptor {
	cd := &circuits.Descriptor{
		Signature: circuits.Signature{
			Name: circuits.Name(apiCd.CircuitSignature.Name),
			Args: make(map[string]string, len(apiCd.CircuitSignature.Args)),
		},
		ID:          circuits.ID(apiCd.CircuitID.CircuitID),
		NodeMapping: make(map[string]pkg.NodeID, len(apiCd.NodeMapping)),
		Evaluator:   pkg.NodeID(apiCd.Evaluator.NodeId),
	}

	for k, v := range apiCd.CircuitSignature.Args {
		cd.Args[k] = v
	}

	for s, nid := range apiCd.NodeMapping {
		cd.NodeMapping[s] = pkg.NodeID(nid.NodeId)
	}

	return cd
}

func getAPIShare(s *protocols.Share) (*api.Share, error) {
	outShareBytes, err := s.MarshalBinary()
	if err != nil {
		return nil, err
	}
	apiShare := &api.Share{
		Desc: &api.ShareDescriptor{
			ProtocolID:   &api.ProtocolID{ProtocolID: string(s.ProtocolID)},
			ProtocolType: api.ProtocolType(s.ShareMetadata.ProtocolType),
			AggregateFor: make([]*api.NodeID, 0, len(s.From)),
		},
		Share: outShareBytes,
	}
	for nID := range s.From {
		apiShare.Desc.AggregateFor = append(apiShare.Desc.AggregateFor, &api.NodeID{NodeId: string(nID)})
	}
	return apiShare, nil
}

// TODO: revamp proto type
func getShareFromAPI(s *api.Share) (protocols.Share, error) {
	desc := s.GetDesc()
	pID := protocols.ID(desc.GetProtocolID().GetProtocolID())
	pType := protocols.Type(desc.ProtocolType)
	share := pType.Share()
	if share == nil {
		return protocols.Share{}, fmt.Errorf("unknown share type: %s", pType)
	}
	ps := protocols.Share{
		ShareMetadata: protocols.ShareMetadata{
			ProtocolID:   pID,
			ProtocolType: pType,
			From:         make(utils.Set[pkg.NodeID]),
		},
		MHEShare: share,
	}
	for _, nid := range desc.AggregateFor {
		ps.From.Add(pkg.NodeID(nid.NodeId))
	}

	err := ps.MHEShare.UnmarshalBinary(s.GetShare())
	if err != nil {
		return protocols.Share{}, err
	}
	return ps, nil
}
