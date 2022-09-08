package pkg

import (
	"sync"

	"github.com/ldsec/helium/pkg/api"
	"github.com/tuneinsight/lattigo/v3/rlwe"
)

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

func (ct Ciphertext) ToGRPC() api.Ciphertext {
	ctBytes, err := ct.MarshalBinary()
	if err != nil {
		panic(err)
	}
	typ := api.CiphertextType(ct.Type)
	return api.Ciphertext{
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
	return
}

func (ctt CiphertextType) String() string {
	if ctt < 0 || int(ctt) > len(typeToString) {
		return "invalid"
	}
	return typeToString[ctt]
}
