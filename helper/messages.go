package helper

import (
	"fmt"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/api/pb"
	"github.com/ChristianMct/helium/circuits"
	"github.com/ChristianMct/helium/node"
	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/utils"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// ---- node events

func getNodeEvent(ev node.Event) (*pb.NodeEvent, error) {
	switch {
	case ev.Protocol != nil:
		return &pb.NodeEvent{Event: &pb.NodeEvent_ProtocolEvent{ProtocolEvent: GetProtocolEvent(*ev.Protocol)}}, nil
	case ev.Circuit != nil:
		return &pb.NodeEvent{Event: &pb.NodeEvent_CircuitEvent{CircuitEvent: GetCircuitEvent(*ev.Circuit)}}, nil
	}
	return nil, fmt.Errorf("invalid event: neither a protocol nor a circuit event")
}

func toNodeEvent(apiEvent *pb.NodeEvent) (node.Event, error) {
	switch e := apiEvent.Event.(type) {
	case *pb.NodeEvent_ProtocolEvent:
		ev := ToProtocolEvent(e.ProtocolEvent)
		return node.Event{Protocol: &ev}, nil
	case *pb.NodeEvent_CircuitEvent:
		ev := ToCircuitEvent(e.CircuitEvent)
		return node.Event{Circuit: &ev}, nil
	}
	return node.Event{}, fmt.Errorf("invalid event: neither a protocol nor a circuit event")
}

// ---- protocol and circuit events

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

func GetCircuitEvent(event circuits.Event) *pb.CircuitEvent {
	return &pb.CircuitEvent{
		Type:        pb.EventType(event.EventType),
		Descriptor_: GetCircuitDesc(event.Descriptor),
	}
}

func ToCircuitEvent(apiEvent *pb.CircuitEvent) circuits.Event {
	return circuits.Event{
		EventType:  circuits.EventType(apiEvent.Type),
		Descriptor: *ToCircuitDesc(apiEvent.Descriptor_),
	}
}

// ---- descriptors

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
		Signature:    protocols.Signature{Type: protocols.Type(apiPD.ProtocolType)},
		Aggregator:   helium.NodeID(apiPD.Aggregator.NodeId),
		Participants: make([]helium.NodeID, 0, len(apiPD.Participants)),
	}
	if len(apiPD.Args) > 0 {
		desc.Signature.Args = make(map[string]string, len(apiPD.Args))
		for k, v := range apiPD.Args {
			desc.Signature.Args[k] = v
		}
	}
	for _, p := range apiPD.Participants {
		desc.Participants = append(desc.Participants, helium.NodeID(p.NodeId))
	}
	return desc
}

func GetCircuitDesc(cd helium.Descriptor) *pb.CircuitDescriptor {
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

func ToCircuitDesc(apiCd *pb.CircuitDescriptor) *helium.Descriptor {
	cd := &helium.Descriptor{
		Signature: helium.Signature{
			Name: helium.Name(apiCd.CircuitSignature.Name),
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

// ---- shares and operands

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

func GetOperand(op *helium.Operand) (*pb.Ciphertext, error) {
	if op == nil || op.Ciphertext == nil {
		return nil, fmt.Errorf("operand has no ciphertext")
	}
	ctBytes, err := op.Ciphertext.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &pb.Ciphertext{
		Metadata:   &pb.CiphertextMetadata{Id: &pb.CiphertextID{CiphertextId: string(op.ID)}},
		Ciphertext: ctBytes,
	}, nil
}

func ToOperand(apiCt *pb.Ciphertext) (*helium.Operand, error) {
	op := &helium.Operand{
		ID:         helium.OperandID(apiCt.GetMetadata().GetId().GetCiphertextId()),
		Ciphertext: new(rlwe.Ciphertext),
	}
	if err := op.ID.Validate(); err != nil {
		return nil, err
	}
	if err := op.Ciphertext.UnmarshalBinary(apiCt.Ciphertext); err != nil {
		return nil, err
	}
	return op, nil
}
