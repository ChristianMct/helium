package node

import (
	"github.com/ldsec/helium/pkg/circuits"
	"github.com/ldsec/helium/pkg/services/setup"
)

type App struct {
	SetupDescription *setup.Description
	Circuits         map[circuits.Name]circuits.Circuit
}
