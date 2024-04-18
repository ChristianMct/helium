package node

import (
	"fmt"

	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/services/compute"
	"github.com/ChristianMct/helium/services/setup"
	"github.com/ChristianMct/helium/sessions"
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
				inshares:             make(chan protocols.Share),
				getAggregationOutput: t.GetAggregationOutput,
			},
		},
		computeTransport: computeTransport{
			protocolTransport: protocolTransport{
				outshares:            outShares,
				inshares:             make(chan protocols.Share),
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
	outshares            chan<- protocols.Share
	inshares             chan protocols.Share
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
	putCiphertext func(ctx context.Context, ct sessions.Ciphertext) error
	getCiphertext func(ctx context.Context, ctID sessions.CiphertextID) (*sessions.Ciphertext, error)
}

func (n *computeTransport) PutCiphertext(ctx context.Context, ct sessions.Ciphertext) error {
	return n.putCiphertext(ctx, ct)
}

func (n *computeTransport) GetCiphertext(ctx context.Context, ctID sessions.CiphertextID) (*sessions.Ciphertext, error) {
	return n.getCiphertext(ctx, ctID)
}

type testTransport struct {
	hid            sessions.NodeID
	helperSetupSrv *setup.Service
	helperCompSrv  *compute.Service
	*protocols.TestTransport
}

func NewTestTransport(hid sessions.NodeID, helperSetupSrv *setup.Service, helperCompSrv *compute.Service) *testTransport {
	tt := &testTransport{
		hid:            hid,
		TestTransport:  protocols.NewTestTransport(),
		helperSetupSrv: helperSetupSrv,
		helperCompSrv:  helperCompSrv,
	}
	return tt
}

func (tt testTransport) TransportFor(nid sessions.NodeID) Transport {
	if nid == tt.hid {
		return tt
	}
	ttc := &testTransport{
		TestTransport:  tt.TestTransport.TransportFor(nid),
		helperSetupSrv: tt.helperSetupSrv,
		helperCompSrv:  tt.helperCompSrv,
	}
	return ttc
}

func (tt testTransport) GetAggregationOutput(ctx context.Context, pd protocols.Descriptor) (*protocols.AggregationOutput, error) {
	return tt.helperSetupSrv.GetAggregationOutput(ctx, pd)
}

func (tt testTransport) PutCiphertext(ctx context.Context, ct sessions.Ciphertext) error {
	return tt.helperCompSrv.PutCiphertext(ctx, ct)
}

func (tt testTransport) GetCiphertext(ctx context.Context, ctID sessions.CiphertextID) (*sessions.Ciphertext, error) {
	return tt.helperCompSrv.GetCiphertext(ctx, ctID)
}
