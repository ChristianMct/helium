package protocols

import (
	"encoding/json"
	"fmt"

	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/utils"
)

const protocolLogging = false

type ShareQuery struct {
	ShareDescriptor
	Result chan Share
}

type Status int32

type Descriptor struct {
	Signature    Signature
	Participants []pkg.NodeID
	Aggregator   pkg.NodeID
}

func (d Descriptor) ID() pkg.ProtocolID {
	return pkg.ProtocolID(fmt.Sprintf("%s-%x", d.Signature, HashOfPartList(d.Participants)))
}

const hidHashHexCharCount = 4

func (d Descriptor) HID() pkg.ProtocolID {
	h := HashOfPartList(d.Participants)
	return pkg.ProtocolID(fmt.Sprintf("%s-%x", d.Signature, h[:hidHashHexCharCount>>1]))
}

func (pd Descriptor) String() string {
	return fmt.Sprintf("{ID: %v, Type: %v, Args: %v, Aggregator: %v, Participants: %v}",
		pd.HID(), pd.Signature.Type, pd.Signature.Args, pd.Aggregator, pd.Participants)
}

func (pd Descriptor) MarshalBinary() (b []byte, err error) {
	return json.Marshal(pd)
}

func (pd *Descriptor) UnmarshalBinary(b []byte) (err error) {
	return json.Unmarshal(b, &pd)
}

func GetParticipants(sig Signature, onlineNodes utils.Set[pkg.NodeID], threshold int) ([]pkg.NodeID, error) {
	if len(onlineNodes) < threshold {
		return nil, fmt.Errorf("not enough online node")
	}

	available := onlineNodes.Copy()
	selected := utils.NewEmptySet[pkg.NodeID]()
	needed := threshold
	if sig.Type == DEC {
		target := pkg.NodeID(sig.Args["target"])
		selected.Add(target)
		available.Remove(target)
		needed--
	}
	selected.AddAll(utils.GetRandomSetOfSize(needed, available))
	return selected.Elements(), nil

}
