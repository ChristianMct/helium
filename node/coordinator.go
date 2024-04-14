package node

import (
	"github.com/ChristianMct/helium/circuit"
	"github.com/ChristianMct/helium/coord"
	"github.com/ChristianMct/helium/coordinator"
	"github.com/ChristianMct/helium/protocol"
	"github.com/ChristianMct/helium/transport/centralized"
	"golang.org/x/net/context"
)

type Event struct {
	ProtocolEvent *protocol.Event
	CircuitEvent  *circuit.Event
}

type Coordinator coord.Coordinator[Event]

type setupCoordinator struct {
	incoming, outgoing chan protocol.Event
}

type computeCoordinator struct {
	incoming, outgoing chan circuit.Event
}

type CentralizedCoordinator struct {
	srv *centralized.HeliumServer

	setupCoordinator
	computeCoordinator

	done chan struct{}
}

func NewCentralizedCoordinator(srv *centralized.HeliumServer) *CentralizedCoordinator {

	cc := &CentralizedCoordinator{
		srv:                srv,
		setupCoordinator:   setupCoordinator{outgoing: make(chan protocol.Event)},
		computeCoordinator: computeCoordinator{outgoing: make(chan circuit.Event)},
		done:               make(chan struct{}),
	}

	go func() {
		for ev := range cc.setupCoordinator.outgoing {
			pev := ev
			cc.srv.AppendEventToLog(coordinator.Event{ProtocolEvent: &pev})
		}
		close(cc.done)
	}()

	go func() {
		for ev := range cc.computeCoordinator.outgoing {
			pev := ev
			cc.srv.AppendEventToLog(coordinator.Event{ProtocolEvent: &pev})
		}
		close(cc.done)
	}()

	return cc
}

func (cc *CentralizedCoordinator) Register(ctx context.Context) (evChan *protocol.EventChannel, present int, err error) {
	evChan = &protocol.EventChannel{
		Incoming: cc.incoming,
		Outgoing: cc.outgoing,
	}
	return evChan, 0, nil
}

type CentralizedCoordinatorClient struct {
	cli *centralized.HeliumClient

	incoming, outgoing chan protocol.Event

	done chan struct{}
}

func NewCentralizedCoordinatorClient(cli *centralized.HeliumClient) *CentralizedCoordinatorClient {

	cc := &CentralizedCoordinatorClient{
		cli:      cli,
		incoming: make(chan protocol.Event),
		outgoing: make(chan protocol.Event),
		done:     make(chan struct{}),
	}

	return cc
}

func (cc *CentralizedCoordinatorClient) Register(ctx context.Context) (evChan *protocol.EventChannel, present int, err error) {

	// events, present, err := cc.cli.Register(ctx)
	// if err != nil {
	// 	return nil, nil, err
	// }

	evChan = &protocol.EventChannel{
		Incoming: cc.incoming,
		Outgoing: cc.outgoing,
	}
	return evChan, 0, nil
}
