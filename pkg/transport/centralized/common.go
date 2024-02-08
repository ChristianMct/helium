package centralized

import (
	"fmt"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/circuits"
	"github.com/ldsec/helium/pkg/coordinator"
	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/protocols"
	"github.com/ldsec/helium/pkg/utils"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func getApiEvent(event coordinator.Event) *api.Event {
	apiEvent := &api.Event{
		EventTime: timestamppb.New(event.Time),
	}
	if event.CircuitEvent != nil {
		apiEvent.CircuitEvent = &api.CircuitEvent{
			Type: api.EventType(event.CircuitEvent.EventType),
			Descriptor_: &api.ComputeSignature{
				CircuitName: event.CircuitName,
				CircuitID:   string(event.CircuitID),
			},
		}
	}
	if event.ProtocolEvent != nil {
		apiDesc := getAPIProtocolDesc(&event.ProtocolEvent.Descriptor)
		apiEvent.ProtocolEvent = &api.ProtocolEvent{Type: api.EventType(event.ProtocolEvent.EventType), Descriptor_: apiDesc}
	}
	return apiEvent
}

func getEventFromAPI(apiEvent *api.Event) coordinator.Event {
	event := coordinator.Event{
		Time: apiEvent.EventTime.AsTime(),
	}
	if apiEvent.CircuitEvent != nil {
		event.CircuitEvent = &coordinator.CircuitEvent{
			EventType: coordinator.EventType(apiEvent.ProtocolEvent.Type),
			Signature: circuits.Signature{
				CircuitName: apiEvent.CircuitEvent.Descriptor_.CircuitName,
				CircuitID:   pkg.CircuitID(apiEvent.CircuitEvent.Descriptor_.CircuitID),
			},
		}
	}
	if apiEvent.ProtocolEvent != nil {
		event.ProtocolEvent = &coordinator.ProtocolEvent{
			EventType:  coordinator.EventType(apiEvent.ProtocolEvent.Type),
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

func getAPIShare(s *protocols.Share) (*api.Share, error) {
	outShareBytes, err := s.MarshalBinary()
	if err != nil {
		return nil, err
	}
	apiShare := &api.Share{
		Desc: &api.ShareDescriptor{
			ProtocolID:   &api.ProtocolID{ProtocolID: string(s.ProtocolID)},
			ProtocolType: api.ProtocolType(s.Type),
			Round:        &s.Round,
			Sender:       &api.NodeID{NodeId: string(s.From)},
			Receivers:    make([]*api.NodeID, 0, len(s.To)),
			AggregateFor: make([]*api.NodeID, 0, len(s.AggregateFor)),
		},
		Share: outShareBytes,
	}
	for _, nID := range s.To {
		apiShare.Desc.Receivers = append(apiShare.Desc.Receivers, &api.NodeID{NodeId: string(nID)})
	}
	for nID := range s.AggregateFor {
		apiShare.Desc.AggregateFor = append(apiShare.Desc.AggregateFor, &api.NodeID{NodeId: string(nID)})
	}
	return apiShare, nil
}

func getShareFromAPI(s *api.Share) (protocols.Share, error) {
	desc := s.GetDesc()
	pID := pkg.ProtocolID(desc.GetProtocolID().GetProtocolID())
	pType := protocols.Type(desc.ProtocolType)
	share := pType.Share()
	if share == nil {
		return protocols.Share{}, fmt.Errorf("unknown share type: %s", pType)
	}
	ps := protocols.Share{
		ShareDescriptor: protocols.ShareDescriptor{
			ProtocolID:   pID,
			Type:         pType,
			Round:        desc.GetRound(),
			From:         pkg.NodeID(desc.GetSender().GetNodeId()),
			To:           make([]pkg.NodeID, 0, len(desc.GetReceivers())),
			AggregateFor: make(utils.Set[pkg.NodeID]),
		},
		MHEShare: share,
	}
	for _, nid := range desc.GetReceivers() {
		ps.To = append(ps.To, pkg.NodeID(nid.NodeId))
	}
	for _, nid := range desc.AggregateFor {
		ps.AggregateFor.Add(pkg.NodeID(nid.NodeId))
	}

	err := ps.MHEShare.UnmarshalBinary(s.GetShare())
	if err != nil {
		return protocols.Share{}, err
	}
	return ps, nil
}
