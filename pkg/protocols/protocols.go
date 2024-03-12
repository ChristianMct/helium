// package protocols implements the MHE protocol execution.
// It uses Lattigo as the underlying MHE library.
package protocols

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/utils"
)

const (
	protocolLogging     = false // whether to log events in protocol execution
	hidHashHexCharCount = 4     // number of hex characters display in the human-readable id
)

// Signature is a protocol prototype. In analogy to a function signature, it
// describes the type of the protocol and the arguments it expects.
type Signature struct {
	Type Type
	Args map[string]string
}

// Descriptor is a protocol instance. It is a complete description of
// a protocol's execution, by complementing the Signature with a role
// assignment.
//
// Multiple protocol instances can share the same signature, but have
// different descriptors (e.g., in the case of a failure).
type Descriptor struct {
	Signature
	Participants []pkg.NodeID
	Aggregator   pkg.NodeID
}

// Input is a type for protocol inputs.
type Input interface{}

// Output is a type for protocol outputs.
// It contains the result of the protocol execution or an error if the
// protocol execution has failed.
type Output struct {
	Result interface{}
	Error  error
}

// Share is a type for the nodes' protocol shares.
type Share struct {
	ShareMetadata
	MHEShare LattigoShare
}

// ShareMetadata retains the necessary information for the framework to
// identify the share and the protocol it belongs to.
type ShareMetadata struct {
	pkg.ProtocolID
	Type
	From utils.Set[pkg.NodeID]
}

type OutputKey interface{}

type CRP interface{}

type AggregationOutput struct {
	Share      Share
	Descriptor Descriptor
	Error      error
}

type Instance interface {
	ID() pkg.ProtocolID
	Desc() Descriptor

	AllocateShare() Share
	GenShare(*Share) error
	Aggregate(ctx context.Context, incoming <-chan Share) (chan AggregationOutput, error)
	HasShareFrom(pkg.NodeID) bool
	Output(agg AggregationOutput) chan Output
}

func (t Signature) String() string {
	args := make(sort.StringSlice, 0, len(t.Args))
	for argname, argval := range t.Args {
		args = append(args, fmt.Sprintf("%s=%s", argname, argval))
	}
	sort.Sort(args)
	return fmt.Sprintf("%s(%s)", t.Type, strings.Join(args, ","))
}

func (s Signature) Equals(other Signature) bool {
	if s.Type != other.Type {
		return false
	}
	for k, v := range s.Args {
		vOther, has := other.Args[k]
		if !has || v != vOther {
			return false
		}
	}
	return true
}

func (d Descriptor) ID() pkg.ProtocolID {
	return pkg.ProtocolID(fmt.Sprintf("%s-%x", d.Signature, HashOfPartList(d.Participants)))
}

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
