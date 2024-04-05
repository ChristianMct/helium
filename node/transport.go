package node

import (
	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/coordinator"
	"github.com/ChristianMct/helium/protocol"
	"golang.org/x/net/context"
)

type protocolTransport struct {
	outshares, inshares  chan protocol.Share
	getAggregationOutput func(context.Context, protocol.Descriptor) (*protocol.AggregationOutput, error)
}

func (n *protocolTransport) IncomingShares() <-chan protocol.Share {
	return n.inshares
}

func (n *protocolTransport) OutgoingShares() chan<- protocol.Share {
	return n.outshares
}

func (n *protocolTransport) GetAggregationOutput(ctx context.Context, pd protocol.Descriptor) (*protocol.AggregationOutput, error) {
	return n.getAggregationOutput(ctx, pd)
}

type computeTransport struct {
	protocolTransport
	putCiphertext func(ctx context.Context, ct helium.Ciphertext) error
	getCiphertext func(ctx context.Context, ctID helium.CiphertextID) (*helium.Ciphertext, error)
}

func (n *computeTransport) PutCiphertext(ctx context.Context, ct helium.Ciphertext) error {
	return n.putCiphertext(ctx, ct)
}

func (n *computeTransport) GetCiphertext(ctx context.Context, ctID helium.CiphertextID) (*helium.Ciphertext, error) {
	return n.getCiphertext(ctx, ctID)
}

type protocolCoordinator struct {
	incoming, outgoing chan protocol.Event
}

func (hcp *protocolCoordinator) Incoming() <-chan protocol.Event {
	return hcp.incoming
}

func (hcp *protocolCoordinator) Outgoing() chan<- protocol.Event {
	return hcp.outgoing
}

type coordinatorT struct {
	incoming, outgoing chan coordinator.Event
}

func (hcp *coordinatorT) Incoming() <-chan coordinator.Event {
	return hcp.incoming
}

func (hcp *coordinatorT) Outgoing() chan<- coordinator.Event {
	return hcp.outgoing
}
