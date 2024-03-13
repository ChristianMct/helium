package node

import (
	"github.com/ldsec/helium/pkg"
	"github.com/ldsec/helium/pkg/coordinator"
	"github.com/ldsec/helium/pkg/protocols"
	"golang.org/x/net/context"
)

type protocolTransport struct {
	outshares, inshares  chan protocols.Share
	getAggregationOutput func(context.Context, protocols.Descriptor) (*protocols.AggregationOutput, error)
}

func (n *protocolTransport) IncomingShares() <-chan protocols.Share {
	return n.inshares
}

func (n *protocolTransport) OutgoingShares() chan<- protocols.Share {
	return n.outshares
}

func (n *protocolTransport) GetAggregationOutput(ctx context.Context, pd protocols.Descriptor) (*protocols.AggregationOutput, error) {
	return n.getAggregationOutput(ctx, pd)
}

type computeTransport struct {
	protocolTransport
	putCiphertext func(ctx context.Context, ct pkg.Ciphertext) error
	getCiphertext func(ctx context.Context, ctID pkg.CiphertextID) (*pkg.Ciphertext, error)
}

func (n *computeTransport) PutCiphertext(ctx context.Context, ct pkg.Ciphertext) error {
	return n.putCiphertext(ctx, ct)
}

func (n *computeTransport) GetCiphertext(ctx context.Context, ctID pkg.CiphertextID) (*pkg.Ciphertext, error) {
	return n.getCiphertext(ctx, ctID)
}

type protocolCoordinator struct {
	incoming, outgoing chan protocols.Event
}

func (hcp *protocolCoordinator) Incoming() <-chan protocols.Event {
	return hcp.incoming
}

func (hcp *protocolCoordinator) Outgoing() chan<- protocols.Event {
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
