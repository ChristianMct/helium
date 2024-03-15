package centralized

import (
	"fmt"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/circuits"
	"github.com/ChristianMct/helium/coordinator"
	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/transport/pb"
	"github.com/ChristianMct/helium/utils"
)

func getAPIEvent(event coordinator.Event) *pb.Event {
	apiEvent := &pb.Event{}
	if event.CircuitEvent != nil {
		apiEvent.CircuitEvent = &pb.CircuitEvent{
			Type:        pb.EventType(event.CircuitEvent.EventType),
			Descriptor_: getAPICircuitDesc(event.CircuitEvent.Descriptor),
		}
	}
	if event.ProtocolEvent != nil {
		apiDesc := getAPIProtocolDesc(&event.ProtocolEvent.Descriptor)
		apiEvent.ProtocolEvent = &pb.ProtocolEvent{Type: pb.EventType(event.ProtocolEvent.EventType), Descriptor_: apiDesc}
	}
	return apiEvent
}

func getEventFromAPI(apiEvent *pb.Event) coordinator.Event {
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

func getAPIProtocolDesc(pd *protocols.Descriptor) *pb.ProtocolDescriptor {
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

func getProtocolDescFromAPI(apiPD *pb.ProtocolDescriptor) *protocols.Descriptor {
	desc := &protocols.Descriptor{
		Signature:    protocols.Signature{Type: protocols.Type(apiPD.ProtocolType), Args: make(map[string]string)},
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

func getAPICircuitDesc(cd circuits.Descriptor) *pb.CircuitDescriptor {
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

func getCircuitDescFromAPI(apiCd *pb.CircuitDescriptor) *circuits.Descriptor {
	cd := &circuits.Descriptor{
		Signature: circuits.Signature{
			Name: circuits.Name(apiCd.CircuitSignature.Name),
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

func getAPIShare(s *protocols.Share) (*pb.Share, error) {
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

func getShareFromAPI(s *pb.Share) (protocols.Share, error) {
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
			From:         make(utils.Set[helium.NodeID]),
		},
		MHEShare: share,
	}
	for _, nid := range desc.AggregateFor {
		ps.From.Add(helium.NodeID(nid.NodeId))
	}

	err := ps.MHEShare.UnmarshalBinary(s.GetShare())
	if err != nil {
		return protocols.Share{}, err
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
