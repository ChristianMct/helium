package helium

import (
	"github.com/ChristianMct/helium/circuits"
)

// App represents an Helium application. It specifes the setup phase
// and declares the circuits that can be executed by the nodes.
type App struct {
	SetupDescription *SetupDescription
	Circuits         map[circuits.Name]circuits.Circuit
}
