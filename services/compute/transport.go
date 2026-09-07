package compute

import (
	"context"

	"github.com/ChristianMct/helium/circuits"
	"github.com/ChristianMct/helium/coordinator"
	"github.com/ChristianMct/helium/sessions"
)

// Transport defines the transport interface necessary for the compute service.
// In the current implementation (helper-assisted setting), this corresponds to the helper interface.
type Transport interface {
	// PutCiphertext registers a ciphertext within the transport
	PutCiphertext(ctx context.Context, ct sessions.Ciphertext) error

	// GetCiphertext requests a ciphertext from the transport.
	GetCiphertext(ctx context.Context, ctID sessions.CiphertextID) (*sessions.Ciphertext, error)
}

// LogCoordinator is a Coordinator backed by an in-memory coordinator.Log.
// It is used for tests and for the evaluator's local service.
type LogCoordinator struct {
	*coordinator.Log[circuits.Event]
}

// NewLogCoordinator creates a LogCoordinator over a new log.
func NewLogCoordinator() *LogCoordinator {
	return &LogCoordinator{Log: coordinator.NewLog[circuits.Event]()}
}

// Register implements Coordinator.
func (lc *LogCoordinator) Register(ctx context.Context) (past []circuits.Event, live <-chan circuits.Event, err error) {
	past, live = lc.Log.Register(ctx)
	return past, live, nil
}

// Publish implements Coordinator.
func (lc *LogCoordinator) Publish(_ context.Context, ev circuits.Event) error {
	return lc.Log.Append(ev)
}

// testNodeTrans is an in-process Transport routing ciphertexts to the helper's service.
type testNodeTrans struct {
	helperSrv *Service
}

func newTestTransport(helperSrv *Service) *testNodeTrans {
	return &testNodeTrans{helperSrv: helperSrv}
}

func (tt *testNodeTrans) PutCiphertext(ctx context.Context, ct sessions.Ciphertext) error {
	return tt.helperSrv.PutCiphertext(ctx, ct)
}

func (tt *testNodeTrans) GetCiphertext(ctx context.Context, ctID sessions.CiphertextID) (*sessions.Ciphertext, error) {
	return tt.helperSrv.GetCiphertext(ctx, ctID)
}
