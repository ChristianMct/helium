package helium

import (
	"context"

	"github.com/ChristianMct/helium/circuits"
)

// App represents an Helium application. It specifies the setup phase, declares the
// circuits that can be evaluated by the nodes, and provides the Main function run by
// every node.
type App struct {
	// SetupDescription describes the MHE setup required by the application.
	SetupDescription *SetupDescription
	// Circuits is the library of circuits of the application.
	Circuits map[circuits.Name]circuits.Circuit
	// Main is the application's function, run by every node once the setup phase has
	// started. It evaluates circuits and runs protocols through the Runtime; a node
	// takes part only in the circuits and protocols its Main requests. A nil Main only
	// takes part in the setup phase.
	Main func(ctx context.Context, rt *Runtime) error
}
