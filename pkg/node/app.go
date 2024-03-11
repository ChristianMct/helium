package node

import (
	"github.com/ldsec/helium/pkg/circuits"
	"github.com/ldsec/helium/pkg/services/setup"
)

// App represents an Helium application. It specifes the setup phase
// and declares the circuits that can be executed by the nodes.
type App struct {
	SetupDescription *setup.Description
	Circuits         map[circuits.Name]circuits.Circuit
}
