package node

import (
	"context"
	"fmt"

	"github.com/ChristianMct/helium/coord"
	"github.com/ChristianMct/helium/services/compute"
	"github.com/ChristianMct/helium/services/setup"
)

type Event struct {
	SetupEvent   *setup.Event
	ComputeEvent *compute.Event
}

func (ev Event) IsCompute() bool {
	return ev.ComputeEvent != nil
}

func (ev Event) IsSetup() bool {
	return ev.SetupEvent != nil
}

type Coordinator coord.Coordinator[Event]

type setupCoordinator struct {
	incoming, outgoing chan setup.Event
}

type computeCoordinator struct {
	incoming, outgoing chan compute.Event
}

type ServicesCoordinator struct {
	setupCoordinator
	computeCoordinator

	setupCoordDone, computeCoordDone chan struct{}
}

func newServicesCoordinator(ctx context.Context, upstream Coordinator) (*ServicesCoordinator, error) {
	sc := &ServicesCoordinator{
		setupCoordinator:   setupCoordinator{outgoing: make(chan setup.Event)},
		computeCoordinator: computeCoordinator{outgoing: make(chan compute.Event)},
	}

	upstreamChan, present, err := upstream.Register(ctx)
	if err != nil {
		return nil, err
	}

	setupEvs := make([]setup.Event, 0, present)
	computeEvs := make([]compute.Event, 0, present)
	for i := 0; i < present; i++ {
		ev := <-upstreamChan.Incoming
		switch {
		case ev.SetupEvent != nil:
			setupEvs = append(setupEvs, *ev.SetupEvent)
		case ev.ComputeEvent != nil:
			computeEvs = append(computeEvs, *ev.ComputeEvent)
		default:
			return nil, fmt.Errorf("invalid node event: not a setup nor a compute event")
		}
	}

	sc.setupCoordinator.incoming = make(chan setup.Event, len(setupEvs))
	for _, ev := range setupEvs {
		sc.setupCoordinator.incoming <- ev
	}

	sc.computeCoordinator.incoming = make(chan compute.Event, len(computeEvs))
	for _, ev := range computeEvs {
		sc.computeCoordinator.incoming <- ev
	}

	go func() {
		for ev := range upstreamChan.Incoming {
			switch {
			case ev.SetupEvent != nil:
				sc.setupCoordinator.incoming <- *ev.SetupEvent
			case ev.ComputeEvent != nil:
				sc.computeCoordinator.incoming <- *ev.ComputeEvent
			default:
				panic(fmt.Errorf("invalid node event: not a setup nor a compute event")) // TODO
			}
		}
		close(sc.setupCoordinator.incoming)
		close(sc.computeCoordinator.incoming)
	}()

	sc.setupCoordDone = make(chan struct{})
	sc.computeCoordDone = make(chan struct{})

	go func() {
		for ev := range sc.setupCoordinator.outgoing {
			ev := ev
			upstreamChan.Outgoing <- Event{SetupEvent: &ev}
		}
		close(sc.setupCoordDone)
	}()

	go func() {
		for ev := range sc.computeCoordinator.outgoing {
			ev := ev
			upstreamChan.Outgoing <- Event{ComputeEvent: &ev}
		}
		close(sc.computeCoordDone)
	}()

	go func() {
		<-sc.setupCoordDone
		//<-sc.computeDone
		if upstreamChan.Outgoing != nil {
			close(upstreamChan.Outgoing)
		}
	}()

	return sc, nil
}

func (sc setupCoordinator) Register(ctx context.Context) (evChan *coord.Channel[setup.Event], present int, err error) {
	evChan = &coord.Channel[setup.Event]{
		Incoming: sc.incoming,
		Outgoing: sc.outgoing,
	}
	return evChan, len(sc.incoming), nil
}

func (sc computeCoordinator) Register(ctx context.Context) (evChan *coord.Channel[compute.Event], present int, err error) {
	evChan = &coord.Channel[compute.Event]{
		Incoming: sc.incoming,
		Outgoing: sc.outgoing,
	}
	return evChan, len(sc.incoming), nil
}

// func NewCentralizedCoordinator(srv *centralized.HeliumServer) *CentralizedCoordinator {

// 	cc := &CentralizedCoordinator{
// 		srv:                srv,
// 		setupCoordinator:   setupCoordinator{outgoing: make(chan protocol.Event)},
// 		computeCoordinator: computeCoordinator{outgoing: make(chan circuit.Event)},
// 		done:               make(chan struct{}),
// 	}

// 	go func() {
// 		for ev := range cc.setupCoordinator.outgoing {
// 			pev := ev
// 			cc.srv.AppendEventToLog(coordinator.Event{ProtocolEvent: &pev})
// 		}
// 		close(cc.done)
// 	}()

// 	go func() {
// 		for ev := range cc.computeCoordinator.outgoing {
// 			pev := ev
// 			cc.srv.AppendEventToLog(coordinator.Event{ProtocolEvent: &pev})
// 		}
// 		close(cc.done)
// 	}()

// 	return cc
// }

// func (cc *CentralizedCoordinator) Register(ctx context.Context) (evChan *protocol.EventChannel, present int, err error) {
// 	evChan = &protocol.EventChannel{
// 		Incoming: cc.incoming,
// 		Outgoing: cc.outgoing,
// 	}
// 	return evChan, 0, nil
// }

// type CentralizedCoordinatorClient struct {
// 	cli *centralized.HeliumClient

// 	incoming, outgoing chan protocol.Event

// 	done chan struct{}
// }

// func NewCentralizedCoordinatorClient(cli *centralized.HeliumClient) *CentralizedCoordinatorClient {

// 	cc := &CentralizedCoordinatorClient{
// 		cli:      cli,
// 		incoming: make(chan protocol.Event),
// 		outgoing: make(chan protocol.Event),
// 		done:     make(chan struct{}),
// 	}

// 	return cc
// }

// func (cc *CentralizedCoordinatorClient) Register(ctx context.Context) (evChan *protocol.EventChannel, present int, err error) {

// 	// events, present, err := cc.cli.Register(ctx)
// 	// if err != nil {
// 	// 	return nil, nil, err
// 	// }

// 	evChan = &protocol.EventChannel{
// 		Incoming: cc.incoming,
// 		Outgoing: cc.outgoing,
// 	}
// 	return evChan, 0, nil
// }
