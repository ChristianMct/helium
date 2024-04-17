package node

import (
	"fmt"

	"github.com/ChristianMct/helium/protocol"
	"github.com/ChristianMct/helium/services/compute"
	"github.com/ChristianMct/helium/services/setup"
	"github.com/ChristianMct/helium/session"
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
	putCiphertext func(ctx context.Context, ct session.Ciphertext) error
	getCiphertext func(ctx context.Context, ctID session.CiphertextID) (*session.Ciphertext, error)
}

func (n *computeTransport) PutCiphertext(ctx context.Context, ct session.Ciphertext) error {
	return n.putCiphertext(ctx, ct)
}

func (n *computeTransport) GetCiphertext(ctx context.Context, ctID session.CiphertextID) (*session.Ciphertext, error) {
	return n.getCiphertext(ctx, ctID)
}

type testTransport struct {
	hid            session.NodeID
	helperSetupSrv *setup.Service
	helperCompSrv  *compute.Service
	*protocol.TestTransport

	//clients []chan protocol.Share
}

func NewTestTransport(hid session.NodeID, helperSetupSrv *setup.Service, helperCompSrv *compute.Service) *testTransport {
	tt := &testTransport{
		hid:            hid,
		TestTransport:  protocol.NewTestTransport(),
		helperSetupSrv: helperSetupSrv,
		helperCompSrv:  helperCompSrv,
	}
	return tt
}

func (tt testTransport) TransportFor(nid session.NodeID) Transport {
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

func (tt testTransport) GetAggregationOutput(ctx context.Context, pd protocol.Descriptor) (*protocol.AggregationOutput, error) {
	return tt.helperSetupSrv.GetAggregationOutput(ctx, pd)
}

func (tt testTransport) PutCiphertext(ctx context.Context, ct session.Ciphertext) error {
	return tt.helperCompSrv.PutCiphertext(ctx, ct)
}

func (tt testTransport) GetCiphertext(ctx context.Context, ctID session.CiphertextID) (*session.Ciphertext, error) {
	return tt.helperCompSrv.GetCiphertext(ctx, ctID)
}
