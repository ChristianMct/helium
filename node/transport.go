package node

import (
	"fmt"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/protocol"
	"github.com/ChristianMct/helium/services/compute"
	"github.com/ChristianMct/helium/services/setup"
	"golang.org/x/net/context"
)

type Transport interface {
	setup.Transport
	compute.Transport
}

type setupTransport struct {
	protocolTransport
}

type nodeTransport struct {
	setupTransport
	computeTransport
}

func newServicesTransport(t Transport) *nodeTransport {

	outShares := t.OutgoingShares()
	nt := &nodeTransport{
		setupTransport: setupTransport{
			protocolTransport{
				outshares:            outShares,
				inshares:             make(chan protocol.Share),
				getAggregationOutput: t.GetAggregationOutput,
			},
		},
		computeTransport: computeTransport{
			protocolTransport: protocolTransport{
				outshares:            outShares,
				inshares:             make(chan protocol.Share),
				getAggregationOutput: t.GetAggregationOutput,
			},
			putCiphertext: t.PutCiphertext,
			getCiphertext: t.GetCiphertext,
		},
	}

	go func() {
		inShares := t.IncomingShares()
		for s := range inShares {
			switch {
			case s.ProtocolType.IsSetup():
				nt.setupTransport.inshares <- s
			case s.ProtocolType.IsCompute():
				nt.computeTransport.inshares <- s
			default:
				panic(fmt.Errorf("unknown protocol type"))
			}
		}
		close(nt.setupTransport.inshares)
		close(nt.computeTransport.inshares)
	}()

	return nt
}

type protocolTransport struct {
	outshares            chan<- protocol.Share
	inshares             chan protocol.Share
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

type testTransport struct {
	hid            helium.NodeID
	helperSetupSrv *setup.Service
	helperCompSrv  *compute.Service
	incoming       chan protocol.Share
	outgoing       chan protocol.Share

	//clients []chan protocol.Share
}

func NewTestTransport(hid helium.NodeID, helperSetupSrv *setup.Service, helperCompSrv *compute.Service) *testTransport {
	tt := &testTransport{
		incoming: make(chan protocol.Share),
	}
	return tt
}

func (tt testTransport) TransportFor(nid helium.NodeID) Transport {
	ttc := &testTransport{
		outgoing: tt.incoming,
	}
	return ttc
}

func (tt testTransport) GetAggregationOutput(ctx context.Context, pd protocol.Descriptor) (*protocol.AggregationOutput, error) {
	return tt.helperSetupSrv.GetAggregationOutput(ctx, pd)
}

func (tt testTransport) PutCiphertext(ctx context.Context, ct helium.Ciphertext) error {
	return tt.helperCompSrv.PutCiphertext(ctx, ct)
}

func (tt testTransport) GetCiphertext(ctx context.Context, ctID helium.CiphertextID) (*helium.Ciphertext, error) {
	return tt.helperCompSrv.GetCiphertext(ctx, ctID)
}

func (tt testTransport) IncomingShares() <-chan protocol.Share {
	return tt.incoming
}

func (tt testTransport) OutgoingShares() chan<- protocol.Share {
	return tt.outgoing
}
