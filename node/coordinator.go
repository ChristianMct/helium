package node

import (
	"github.com/ChristianMct/helium/coordinator"
	"github.com/ChristianMct/helium/protocol"
	"github.com/ChristianMct/helium/transport/centralized"
	"golang.org/x/net/context"
)

type CentralizedCoordinator struct {
	srv *centralized.HeliumServer

	incoming, outgoing chan protocol.Event

	done chan struct{}
}

func NewCentralizedCoordinator(srv *centralized.HeliumServer) *CentralizedCoordinator {

	cc := &CentralizedCoordinator{
		srv:      srv,
		incoming: make(chan protocol.Event),
		outgoing: make(chan protocol.Event),
		done:     make(chan struct{}),
	}

	go func() {
		for ev := range cc.outgoing {
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

	events, present, err := cc.cli.Register(ctx)
	if err != nil {
		return nil, nil, err
	}

	evChan = &protocol.EventChannel{
		Incoming: cc.incoming,
		Outgoing: cc.outgoing,
	}
	return evChan, 0, nil
}
