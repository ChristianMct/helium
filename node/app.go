package node

import (
	"github.com/ChristianMct/helium/circuit"
	"github.com/ChristianMct/helium/services/setup"
)

// App represents an Helium application. It specifes the setup phase
// and declares the circuits that can be executed by the nodes.
type App struct {
	SetupDescription *setup.Description
	Circuits         map[circuit.Name]circuit.Circuit
}
