package circuits

import (
	"encoding/json"

	"github.com/ldsec/helium/pkg/pkg"
)

type Signature struct {
	CircuitName string
	CircuitID   pkg.CircuitID
}

type Status int32

const (
	Completed Status = iota
	Created
	Executing
)

type Update struct {
	Signature
	Status
	//*protocols.StatusUpdate
}

func (u Update) String() string {
	s, err := json.Marshal(u)
	if err != nil {
		panic(err)
	}
	return string(s)
}
