// Package api implements a translation layer between the protobuf and internal Helium types.
package api

import (
	"fmt"

	"github.com/ChristianMct/helium/api/pb"
	"github.com/ChristianMct/helium/circuits"
	"github.com/ChristianMct/helium/node"
	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/services/compute"
	"github.com/ChristianMct/helium/services/setup"
	"github.com/ChristianMct/helium/sessions"
	"github.com/ChristianMct/helium/utils"
)

func GetProtocolEvent(event protocols.Event) *pb.ProtocolEvent {
	return &pb.ProtocolEvent{
		Type:        pb.EventType(event.EventType),
		Descriptor_: GetProtocolDesc(&event.Descriptor),
	}
}

func ToProtocolEvent(apiEvent *pb.ProtocolEvent) protocols.Event {
	return protocols.Event{
		EventType:  protocols.EventType(apiEvent.Type),
		Descriptor: *ToProtocolDesc(apiEvent.Descriptor_),
	}
}

func GetSetupEvent(event setup.Event) *pb.SetupEvent {
	return &pb.SetupEvent{
		ProtocolEvent: GetProtocolEvent(event.Event),
	}
}

func ToSetupEvent(apiEvent *pb.SetupEvent) setup.Event {
	return setup.Event{
		Event: ToProtocolEvent(apiEvent.ProtocolEvent),
	}
}

func GetComputeEvent(event compute.Event) *pb.ComputeEvent {
	apiEvent := &pb.ComputeEvent{}
	if event.CircuitEvent != nil {
		apiEvent.CircuitEvent = &pb.CircuitEvent{
			Type:        pb.EventType(event.CircuitEvent.EventType),
			Descriptor_: GetCircuitDesc(event.CircuitEvent.Descriptor),
		}
	}
	if event.ProtocolEvent != nil {
		apiEvent.ProtocolEvent = &pb.ProtocolEvent{
			Type:        pb.EventType(event.ProtocolEvent.EventType),
			Descriptor_: GetProtocolDesc(&event.ProtocolEvent.Descriptor),
		}
	}
	return apiEvent
}

func ToComputeEvent(apiEvent *pb.ComputeEvent) compute.Event {
	event := compute.Event{}
	if apiEvent.CircuitEvent != nil {
		event.CircuitEvent = &circuits.Event{
			EventType:  circuits.EventType(apiEvent.CircuitEvent.Type),
			Descriptor: *ToCircuitDesc(apiEvent.CircuitEvent.Descriptor_),
		}
	}
	if apiEvent.ProtocolEvent != nil {
		event.ProtocolEvent = &protocols.Event{
			EventType:  protocols.EventType(apiEvent.ProtocolEvent.Type),
			Descriptor: *ToProtocolDesc(apiEvent.ProtocolEvent.Descriptor_),
		}
	}
	return event
}

func GetNodeEvent(event node.Event) *pb.NodeEvent {
	apiEvent := &pb.NodeEvent{}
	if event.IsSetup() {
		apiEvent.Event = &pb.NodeEvent_SetupEvent{SetupEvent: GetSetupEvent(*event.SetupEvent)}
	}
	if event.IsCompute() {
		apiEvent.Event = &pb.NodeEvent_ComputeEvent{ComputeEvent: GetComputeEvent(*event.ComputeEvent)}
	}
	return apiEvent
}

func ToNodeEvent(apiEvent *pb.NodeEvent) node.Event {
	event := node.Event{}
	switch e := apiEvent.Event.(type) {
	case *pb.NodeEvent_SetupEvent:
		ev := ToSetupEvent(e.SetupEvent)
		event.SetupEvent = &ev
	case *pb.NodeEvent_ComputeEvent:
		ev := ToComputeEvent(e.ComputeEvent)
		event.ComputeEvent = &ev
	}
	return event
}

func GetProtocolDesc(pd *protocols.Descriptor) *pb.ProtocolDescriptor {
	apiDesc := &pb.ProtocolDescriptor{
		ProtocolType: pb.ProtocolType(pd.Signature.Type),
		Args:         make(map[string]string, len(pd.Signature.Args)),
		Aggregator:   &pb.NodeID{NodeId: string(pd.Aggregator)},
		Participants: make([]*pb.NodeID, 0, len(pd.Participants)),
	}
	for k, v := range pd.Signature.Args {
		apiDesc.Args[k] = v
	}
	for _, p := range pd.Participants {
		apiDesc.Participants = append(apiDesc.Participants, &pb.NodeID{NodeId: string(p)})
	}
	return apiDesc
}

func ToProtocolDesc(apiPD *pb.ProtocolDescriptor) *protocols.Descriptor {
	desc := &protocols.Descriptor{
		Signature:    protocols.Signature{Type: protocols.Type(apiPD.ProtocolType), Args: make(map[string]string)},
		Aggregator:   sessions.NodeID(apiPD.Aggregator.NodeId),
		Participants: make([]sessions.NodeID, 0, len(apiPD.Participants)),
	}
	for k, v := range apiPD.Args {
		desc.Signature.Args[k] = v
	}
	for _, p := range apiPD.Participants {
		desc.Participants = append(desc.Participants, sessions.NodeID(p.NodeId))
	}
	return desc
}

func GetCircuitDesc(cd circuits.Descriptor) *pb.CircuitDescriptor {
	apiDesc := &pb.CircuitDescriptor{
		CircuitSignature: &pb.CircuitSignature{
			Name: string(cd.Name),
			Args: make(map[string]string, len(cd.Args)),
		},
		CircuitID:   &pb.CircuitID{CircuitID: string(cd.CircuitID)},
		NodeMapping: make(map[string]*pb.NodeID, len(cd.NodeMapping)),
		Evaluator:   &pb.NodeID{NodeId: string(cd.Evaluator)},
	}

	for k, v := range cd.Args {
		apiDesc.CircuitSignature.Args[k] = v
	}

	for s, nid := range cd.NodeMapping {
		apiDesc.NodeMapping[s] = &pb.NodeID{NodeId: string(nid)}
	}

	return apiDesc
}

func ToCircuitDesc(apiCd *pb.CircuitDescriptor) *circuits.Descriptor {
	cd := &circuits.Descriptor{
		Signature: circuits.Signature{
			Name: circuits.Name(apiCd.CircuitSignature.Name),
			Args: make(map[string]string, len(apiCd.CircuitSignature.Args)),
		},
		CircuitID:   sessions.CircuitID(apiCd.CircuitID.CircuitID),
		NodeMapping: make(map[string]sessions.NodeID, len(apiCd.NodeMapping)),
		Evaluator:   sessions.NodeID(apiCd.Evaluator.NodeId),
	}

	for k, v := range apiCd.CircuitSignature.Args {
		cd.Args[k] = v
	}

	for s, nid := range apiCd.NodeMapping {
		cd.NodeMapping[s] = sessions.NodeID(nid.NodeId)
	}

	return cd
}

func GetShare(s *protocols.Share) (*pb.Share, error) {
	outShareBytes, err := s.MarshalBinary()
	if err != nil {
		return nil, err
	}
	apiShare := &pb.Share{
		Metadata: &pb.ShareMetadata{
			ProtocolID:   &pb.ProtocolID{ProtocolID: string(s.ProtocolID)},
			ProtocolType: pb.ProtocolType(s.ShareMetadata.ProtocolType),
			AggregateFor: make([]*pb.NodeID, 0, len(s.From)),
		},
		Share: outShareBytes,
	}
	for nID := range s.From {
		apiShare.Metadata.AggregateFor = append(apiShare.Metadata.AggregateFor, &pb.NodeID{NodeId: string(nID)})
	}
	return apiShare, nil
}

func ToShare(s *pb.Share) (protocols.Share, error) {
	desc := s.GetMetadata()
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
			From:         make(utils.Set[sessions.NodeID]),
		},
		MHEShare: share,
	}
	for _, nid := range desc.AggregateFor {
		ps.From.Add(sessions.NodeID(nid.NodeId))
	}

	err := ps.MHEShare.UnmarshalBinary(s.GetShare())
	if err != nil {
		return protocols.Share{}, err
	}
	return ps, nil
}

func GetCiphertext(ct *sessions.Ciphertext) (*pb.Ciphertext, error) {
	ctBytes, err := ct.MarshalBinary()
	if err != nil {
		return nil, err
	}
	typ := pb.CiphertextType(ct.Type)
	return &pb.Ciphertext{
		Metadata:   &pb.CiphertextMetadata{Id: &pb.CiphertextID{CiphertextId: string(ct.ID)}, Type: &typ},
		Ciphertext: ctBytes,
	}, nil
}

func ToCiphertext(apiCt *pb.Ciphertext) (*sessions.Ciphertext, error) {
	var ct sessions.Ciphertext
	ct.CiphertextMetadata.ID = sessions.CiphertextID(apiCt.Metadata.GetId().CiphertextId)
	ct.CiphertextMetadata.Type = sessions.CiphertextType(apiCt.Metadata.GetType())
	err := ct.Ciphertext.UnmarshalBinary(apiCt.Ciphertext)
	if err != nil {
		return nil, err
	}
	return &ct, nil
}
