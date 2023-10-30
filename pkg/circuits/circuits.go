package circuits

import (
	"encoding/json"

	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/protocols"
)

type Signature struct {
	CircuitName string
	CircuitID   pkg.CircuitID
}

type Status int32

const (
	OK Status = iota
	Running
)

type Update struct {
	Signature
	Status
	*protocols.StatusUpdate
}

func (u Update) String() string {
	s, err := json.Marshal(u)
	if err != nil {
		panic(err)
	}
	return string(s)
}