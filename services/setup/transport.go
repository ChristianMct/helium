package setup

import (
	"context"

	"github.com/ChristianMct/helium/protocol"
	"github.com/ChristianMct/helium/session"
)

// Transport defines the transport interface needed by the setup service.
// In the current implementation, this corresponds to the helper interface.
type Transport interface {
	protocol.Transport
	// GetAggregationOutput returns the aggregation output for the given protocol.
	GetAggregationOutput(context.Context, protocol.Descriptor) (*protocol.AggregationOutput, error)
}

type testNodeTrans struct {
	*protocol.TestTransport
	helperSrv *Service
}

func (tt *testNodeTrans) GetAggregationOutput(ctx context.Context, pd protocol.Descriptor) (*protocol.AggregationOutput, error) {
	return tt.helperSrv.GetAggregationOutput(ctx, pd)
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
