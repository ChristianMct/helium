package compute

import (
	"context"

	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/sessions"
)

// Transport defines the transport interface necessary for the compute service.
// In the current implementation (helper-assisted setting), this corresponds to the helper interface.
type Transport interface {
	protocols.Transport

	// PutCiphertext registers a ciphertext within the transport
	PutCiphertext(ctx context.Context, ct sessions.Ciphertext) error

	// GetCiphertext requests a ciphertext from the transport.
	GetCiphertext(ctx context.Context, ctID sessions.CiphertextID) (*sessions.Ciphertext, error)
}

type testNodeTrans struct {
	*protocols.TestTransport
	helperSrv *Service
}

func (tt *testNodeTrans) PutCiphertext(ctx context.Context, ct sessions.Ciphertext) error {
	return tt.helperSrv.PutCiphertext(ctx, ct)
}

func (tt *testNodeTrans) GetCiphertext(ctx context.Context, ctID sessions.CiphertextID) (*sessions.Ciphertext, error) {
	return tt.helperSrv.GetCiphertext(ctx, ctID)
}

func newTestTransport(helperSrv *Service) *testNodeTrans {
	return &testNodeTrans{TestTransport: protocols.NewTestTransport(), helperSrv: helperSrv}
}

func (tt *testNodeTrans) TransportFor(nid sessions.NodeID) Transport {
	if nid == tt.helperSrv.self {
		return tt
	}
	ttc := &testNodeTrans{
		TestTransport: tt.TestTransport.TransportFor(nid),
		helperSrv:     tt.helperSrv,
	}
	return ttc
}
