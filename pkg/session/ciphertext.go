package pkg

import (
	"fmt"
	"net/url"
	"sync"

	"github.com/ldsec/helium/pkg/api"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

type OperandLabel string

type Operand struct {
	OperandLabel
	*rlwe.Ciphertext
}

type CiphertextType int

const (
	Unspecified CiphertextType = iota + 1
	BFV
	BGV
	CKKS
	RGSW
)

var typeToString = [...]string{"Unspecified", "BFV", "BGV", "CKKS", "RGSW"}

type CiphertextMetadata struct {
	ID   CiphertextID
	Type CiphertextType
}

type CiphertextID string

type Ciphertext struct {
	rlwe.Ciphertext
	CiphertextMetadata
}

type CiphertextStore struct {
	cts   map[CiphertextID]Ciphertext
	mutex sync.RWMutex
}

func NewCiphertextFromGRPC(apiCt *api.Ciphertext) (*Ciphertext, error) {
	var ct Ciphertext
	ct.CiphertextMetadata.ID = CiphertextID(apiCt.Metadata.GetId().CiphertextId)
	ct.CiphertextMetadata.Type = CiphertextType(apiCt.Metadata.GetType())
	err := ct.Ciphertext.UnmarshalBinary(apiCt.Ciphertext)
	if err != nil {
		return nil, err
	}
	return &ct, nil
}

func (id CiphertextID) ToGRPC() *api.CiphertextID {
	return &api.CiphertextID{CiphertextId: string(id)}
}

func (ct Ciphertext) ToGRPC() *api.Ciphertext {
	ctBytes, err := ct.MarshalBinary()
	if err != nil {
		panic(err)
	}
	typ := api.CiphertextType(ct.Type)
	return &api.Ciphertext{
		Metadata:   &api.CiphertextMetadata{Id: &api.CiphertextID{CiphertextId: string(ct.ID)}, Type: &typ},
		Ciphertext: ctBytes,
	}

}

func NewCiphertextStore() *CiphertextStore {
	return &CiphertextStore{cts: make(map[CiphertextID]Ciphertext)}
}

func (cts *CiphertextStore) Store(ct Ciphertext) error {
	cts.mutex.Lock()
	defer cts.mutex.Unlock()
	cts.cts[ct.ID] = ct
	return nil
}

func (cts *CiphertextStore) Load(id CiphertextID) (ct Ciphertext, exists bool) {
	cts.mutex.RLock()
	defer cts.mutex.RUnlock()
	ct, exists = cts.cts[id]
	return ct, exists
}

func (ctt CiphertextType) String() string {
	if ctt < 0 || int(ctt) > len(typeToString) {
		return "invalid"
	}
	return typeToString[ctt]
}

func (opl OperandLabel) ForCircuit(cid CircuitID) OperandLabel {
	nopl, err := url.Parse(string(opl))
	if err != nil {
		panic(fmt.Errorf("invalid operand label: %s", opl))
	}
	nopl.Path = fmt.Sprintf("/%s%s", cid, nopl.Path)
	return OperandLabel(nopl.String())
}

func (opl OperandLabel) ForMapping(nodeMapping map[string]NodeID) OperandLabel {
	if nodeMapping == nil {
		return opl
	}
	nopl, err := url.Parse(string(opl))
	if err != nil {
		panic(fmt.Errorf("invalid operand label: %s", opl))
	}
	if len(nopl.Host) > 0 {
		nodeID, provided := nodeMapping[nopl.Host]
		if !provided {
			panic(fmt.Errorf("no mapping provided for node id %s", nopl.Host))
		}
		nopl.Host = string(nodeID)
	}
	return OperandLabel(nopl.String())
}
