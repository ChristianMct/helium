package setup

import (
	"context"

	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/sessions"
)

// Transport defines the transport interface needed by the setup service.
// In the current implementation, this corresponds to the helper interface.
type Transport interface {
	protocols.Transport
	// GetAggregationOutput returns the aggregation output for the given protocol.
	GetAggregationOutput(context.Context, protocols.Descriptor) (*protocols.AggregationOutput, error)
}

type testNodeTrans struct {
	*protocols.TestTransport
	helperSrv *Service
}

func (tt *testNodeTrans) GetAggregationOutput(ctx context.Context, pd protocols.Descriptor) (*protocols.AggregationOutput, error) {
	return tt.helperSrv.GetAggregationOutput(ctx, pd)
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
