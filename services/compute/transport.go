package compute

import (
	"context"

	"github.com/ChristianMct/helium/protocol"
	"github.com/ChristianMct/helium/session"
)

// Transport defines the transport interface necessary for the compute service.
// In the current implementation (helper-assisted setting), this corresponds to the helper interface.
type Transport interface {
	protocol.Transport

	// PutCiphertext registers a ciphertext within the transport
	PutCiphertext(ctx context.Context, ct session.Ciphertext) error

	// GetCiphertext requests a ciphertext from the transport.
	GetCiphertext(ctx context.Context, ctID session.CiphertextID) (*session.Ciphertext, error)
}

type testNodeTrans struct {
	*protocol.TestTransport
	helperSrv *Service
}

func (tt *testNodeTrans) PutCiphertext(ctx context.Context, ct session.Ciphertext) error {
	return tt.helperSrv.PutCiphertext(ctx, ct)
}

func (tt *testNodeTrans) GetCiphertext(ctx context.Context, ctID session.CiphertextID) (*session.Ciphertext, error) {
	return tt.helperSrv.GetCiphertext(ctx, ctID)
}

func newTestTransport(helperSrv *Service) *testNodeTrans {
	return &testNodeTrans{TestTransport: protocol.NewTestTransport(), helperSrv: helperSrv}
}

func (tt *testNodeTrans) TransportFor(nid session.NodeID) Transport {
	if nid == tt.helperSrv.self {
		return tt
	}
	ttc := &testNodeTrans{
		TestTransport: tt.TestTransport.TransportFor(nid),
		helperSrv:     tt.helperSrv,
	}
	return ttc
}
