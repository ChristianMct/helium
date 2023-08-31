package circuits

import (
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
