package centralized

import (
	"fmt"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/circuit"
	"github.com/ChristianMct/helium/node"
	"github.com/ChristianMct/helium/protocol"
	"github.com/ChristianMct/helium/services/compute"
	"github.com/ChristianMct/helium/services/setup"
	"github.com/ChristianMct/helium/transport/pb"
	"github.com/ChristianMct/helium/utils"
)

func getAPIProtocolEvent(event protocol.Event) *pb.ProtocolEvent {
	return &pb.ProtocolEvent{
		Type:        pb.EventType(event.EventType),
		Descriptor_: getAPIProtocolDesc(&event.Descriptor),
	}
}

func getProtocolEventFromAPI(apiEvent *pb.ProtocolEvent) protocol.Event {
	return protocol.Event{
		EventType:  protocol.EventType(apiEvent.Type),
		Descriptor: *getProtocolDescFromAPI(apiEvent.Descriptor_),
	}
}

func getAPISetupEvent(event setup.Event) *pb.SetupEvent {
	return &pb.SetupEvent{
		ProtocolEvent: getAPIProtocolEvent(event.Event),
	}
}

func getSetupEventFromAPI(apiEvent *pb.SetupEvent) setup.Event {
	return setup.Event{
		Event: getProtocolEventFromAPI(apiEvent.ProtocolEvent),
	}
}

func getAPIComputeEvent(event compute.Event) *pb.ComputeEvent {
	apiEvent := &pb.ComputeEvent{}
	if event.CircuitEvent != nil {
		apiEvent.CircuitEvent = &pb.CircuitEvent{
			Type:        pb.EventType(event.CircuitEvent.EventType),
			Descriptor_: getAPICircuitDesc(event.CircuitEvent.Descriptor),
		}
	}
	if event.ProtocolEvent != nil {
		apiEvent.ProtocolEvent = &pb.ProtocolEvent{
			Type:        pb.EventType(event.ProtocolEvent.EventType),
			Descriptor_: getAPIProtocolDesc(&event.ProtocolEvent.Descriptor),
		}
	}
	return apiEvent
}

func getComputeEventFromAPI(apiEvent *pb.ComputeEvent) compute.Event {
	event := compute.Event{}
	if apiEvent.CircuitEvent != nil {
		event.CircuitEvent = &circuit.Event{
			EventType:  circuit.EventType(apiEvent.CircuitEvent.Type),
			Descriptor: *getCircuitDescFromAPI(apiEvent.CircuitEvent.Descriptor_),
		}
	}
	if apiEvent.ProtocolEvent != nil {
		event.ProtocolEvent = &protocol.Event{
			EventType:  protocol.EventType(apiEvent.ProtocolEvent.Type),
			Descriptor: *getProtocolDescFromAPI(apiEvent.ProtocolEvent.Descriptor_),
		}
	}
	return event
}

func getAPINodeEvent(event node.Event) *pb.NodeEvent {
	apiEvent := &pb.NodeEvent{}
	if event.IsSetup() {
		apiEvent.Event = &pb.NodeEvent_SetupEvent{SetupEvent: getAPISetupEvent(*event.SetupEvent)}
	}
	if event.IsCompute() {
		apiEvent.Event = &pb.NodeEvent_ComputeEvent{ComputeEvent: getAPIComputeEvent(*event.ComputeEvent)}
	}
	return apiEvent
}

func getNodeEventFromAPI(apiEvent *pb.NodeEvent) node.Event {
	event := node.Event{}
	switch e := apiEvent.Event.(type) {
	case *pb.NodeEvent_SetupEvent:
		ev := getSetupEventFromAPI(e.SetupEvent)
		event.SetupEvent = &ev
	case *pb.NodeEvent_ComputeEvent:
		ev := getComputeEventFromAPI(e.ComputeEvent)
		event.ComputeEvent = &ev
	}
	return event
}

func getAPIProtocolDesc(pd *protocol.Descriptor) *pb.ProtocolDescriptor {
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

func getProtocolDescFromAPI(apiPD *pb.ProtocolDescriptor) *protocol.Descriptor {
	desc := &protocol.Descriptor{
		Signature:    protocol.Signature{Type: protocol.Type(apiPD.ProtocolType), Args: make(map[string]string)},
		Aggregator:   helium.NodeID(apiPD.Aggregator.NodeId),
		Participants: make([]helium.NodeID, 0, len(apiPD.Participants)),
	}
	for k, v := range apiPD.Args {
		desc.Signature.Args[k] = v
	}
	for _, p := range apiPD.Participants {
		desc.Participants = append(desc.Participants, helium.NodeID(p.NodeId))
	}
	return desc
}

func getAPICircuitDesc(cd circuit.Descriptor) *pb.CircuitDescriptor {
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

func getCircuitDescFromAPI(apiCd *pb.CircuitDescriptor) *circuit.Descriptor {
	cd := &circuit.Descriptor{
		Signature: circuit.Signature{
			Name: circuit.Name(apiCd.CircuitSignature.Name),
			Args: make(map[string]string, len(apiCd.CircuitSignature.Args)),
		},
		CircuitID:   helium.CircuitID(apiCd.CircuitID.CircuitID),
		NodeMapping: make(map[string]helium.NodeID, len(apiCd.NodeMapping)),
		Evaluator:   helium.NodeID(apiCd.Evaluator.NodeId),
	}

	for k, v := range apiCd.CircuitSignature.Args {
		cd.Args[k] = v
	}

	for s, nid := range apiCd.NodeMapping {
		cd.NodeMapping[s] = helium.NodeID(nid.NodeId)
	}

	return cd
}

func getAPIShare(s *protocol.Share) (*pb.Share, error) {
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

func getShareFromAPI(s *pb.Share) (protocol.Share, error) {
	desc := s.GetMetadata()
	pID := protocol.ID(desc.GetProtocolID().GetProtocolID())
	pType := protocol.Type(desc.ProtocolType)
	share := pType.Share()
	if share == nil {
		return protocol.Share{}, fmt.Errorf("unknown share type: %s", pType)
	}
	ps := protocol.Share{
		ShareMetadata: protocol.ShareMetadata{
			ProtocolID:   pID,
			ProtocolType: pType,
			From:         make(utils.Set[helium.NodeID]),
		},
		MHEShare: share,
	}
	for _, nid := range desc.AggregateFor {
		ps.From.Add(helium.NodeID(nid.NodeId))
	}

	err := ps.MHEShare.UnmarshalBinary(s.GetShare())
	if err != nil {
		return protocol.Share{}, err
	}
	return ps, nil
}

func getAPICiphertext(ct *helium.Ciphertext) (*pb.Ciphertext, error) {
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

func getCiphertextFromAPI(apiCt *pb.Ciphertext) (*helium.Ciphertext, error) {
	var ct helium.Ciphertext
	ct.CiphertextMetadata.ID = helium.CiphertextID(apiCt.Metadata.GetId().CiphertextId)
	ct.CiphertextMetadata.Type = helium.CiphertextType(apiCt.Metadata.GetType())
	err := ct.Ciphertext.UnmarshalBinary(apiCt.Ciphertext)
	if err != nil {
		return nil, err
	}
	return &ct, nil
}
