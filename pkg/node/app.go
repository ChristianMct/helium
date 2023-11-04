package node

import (
	"github.com/ldsec/helium/pkg/services/compute"
	"github.com/ldsec/helium/pkg/services/setup"
)

type App struct {
	SetupDescription   *setup.Description
	ComputeDescription compute.Description
	Circuits           map[string]compute.Circuit
	*compute.InputProvider
}
