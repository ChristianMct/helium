package protocols

import (
	"encoding/json"
	"fmt"

	"github.com/ldsec/helium/pkg/pkg"
)

type ShareQuery struct {
	ShareDescriptor
	Result chan Share
}

type Transport interface {
	OutgoingShares() chan<- Share
	IncomingShares() <-chan Share
}

type Status int32

const (
	OK Status = iota
	Running
	Failed
)

type StatusUpdate struct {
	Descriptor
	Status
}

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
