package grpctrans

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strconv"
	"sync"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/circuits"
	"github.com/ldsec/helium/pkg/coordinator"
	"github.com/ldsec/helium/pkg/pkg"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const SendQueueSize = 100

type client struct {
	//connected bool
	sendQueue chan coordinator.Event
}

type coordinatorTransportServer struct {
	*Transport
	*api.UnimplementedCoordinatorServer

	events   coordinator.Log
	eventsMu sync.RWMutex

	nodes   map[pkg.NodeID]*client
	nodesMu sync.RWMutex

	closing chan struct{}
}

func (ct *coordinatorTransportServer) Send(event coordinator.Event) error {
	ct.eventsMu.Lock()
	ct.events = append(ct.events, event)

	ct.nodesMu.RLock()
	for nodeId, node := range ct.nodes {
		if node.sendQueue != nil {
			select {
			case node.sendQueue <- event:
			default:
				panic(fmt.Errorf("node %s has full send queue", nodeId)) // TODO: handle this by closing stream instead
			}
		}
	}
	ct.nodesMu.RUnlock()
	ct.eventsMu.Unlock()
	return nil
}

func (ct *coordinatorTransportServer) Register(_ *api.Void, stream api.Coordinator_RegisterServer) error {
	nodeId := pkg.SenderIDFromIncomingContext(stream.Context())
	if len(nodeId) == 0 {
		return fmt.Errorf("caller must specify node id for stream")
	}

	ct.Logf("connected %s", nodeId)

	ct.eventsMu.RLock()
	present := len(ct.events)
	pastEvents := ct.events
	ct.nodesMu.Lock()
	node, has := ct.nodes[nodeId]
	if !has {
		panic(fmt.Errorf("unexpected peer id: %s", nodeId))
	}
	if node.sendQueue != nil {
		panic(fmt.Errorf("peer already registered: %s", nodeId))
	}
	sendQueue := make(chan coordinator.Event, 100)
	node.sendQueue = sendQueue
	ct.nodesMu.Unlock()
	ct.eventsMu.RUnlock() // all events after pastEvents will go on the sendQueue

	ct.Logf("registered %s", nodeId)

	var done bool
	stream.SetHeader(metadata.MD{"present": []string{strconv.Itoa(present)}})
	for _, ev := range pastEvents {
		err := stream.Send(getApiEvent(ev))
		if err != nil {
			done = true
			ct.Logf("error while sending past events to %s: %s", nodeId, err)
			break
		}
	}

	// Processes the node's sendQueue. The sendQueue channel is closed when exiting the loop
	cancelled := stream.Context().Done()
	for !done {
		select {
		// received an event to send or closed the queue
		case evt, more := <-sendQueue:
			if more {
				if err := stream.Send(getApiEvent(evt)); err != nil {
					done = true
					ct.Logf("error on stream send for %s: %s", nodeId, err)
				}
			} else {
				done = true
				ct.Logf("update queue for %s closed", nodeId)
			}

		// stream was terminated by the node or the server
		case <-cancelled:
			done = true
			close(sendQueue)
			ct.Logf("stream context done for %s, err = %s", nodeId, stream.Context().Err())

		// the transport is closing
		case <-ct.closing:
			close(sendQueue)
			ct.Logf("transport closing, closing queue for %s", nodeId)
		}
	}

	ct.nodesMu.Lock()
	node.sendQueue = nil
	ct.nodesMu.Unlock()

	return nil
}

func (ct *coordinatorTransportServer) Logf(msg string, v ...any) {
	log.Printf("%s | [CoordTransport] %s\n", ct.id, fmt.Sprintf(msg, v...))
}

type coordinatorTransport struct {
	*coordinatorTransportServer
	api.CoordinatorClient

	id pkg.NodeID
}

func (ct *coordinatorTransport) Register(ctx context.Context) (events <-chan coordinator.Event, present int, err error) {
	stream, err := ct.CoordinatorClient.Register(ctx, &api.Void{})
	if err != nil {
		return nil, 0, err
	}

	present, err = readPresentFromStream(stream)
	if err != nil {
		return nil, 0, err
	}

	eventsStream := make(chan coordinator.Event)
	go func() {
		for {
			apiEvent, err := stream.Recv()
			if err != nil {
				close(eventsStream)
				if !errors.Is(err, io.EOF) {
					ct.Logf("error on stream: %s", err)
				}
				return
			}
			eventsStream <- getEventFromAPI(apiEvent)
		}
	}()
	events = eventsStream
	return
}

func (ct *coordinatorTransport) Send(event coordinator.Event) error {
	if ct.coordinatorTransportServer == nil {
		return fmt.Errorf("transport is not a server")
	}
	return ct.coordinatorTransportServer.Send(event)
}

func (ct *coordinatorTransport) Logf(msg string, v ...any) {
	log.Printf("%s | [CoordTransport] %s\n", ct.id, fmt.Sprintf(msg, v...))
}

func getEventFromAPI(apiEvent *api.Event) coordinator.Event {
	event := coordinator.Event{
		Time: apiEvent.EventTime.AsTime(),
	}
	if apiEvent.CircuitEvent != nil {
		event.CircuitEvent = &coordinator.CircuitEvent{
			EventType: coordinator.EventType(apiEvent.ProtocolEvent.Type),
			Signature: circuits.Signature{
				CircuitName: apiEvent.CircuitEvent.Descriptor_.CircuitName,
				CircuitID:   pkg.CircuitID(apiEvent.CircuitEvent.Descriptor_.CircuitID),
			},
		}
	}
	if apiEvent.ProtocolEvent != nil {
		event.ProtocolEvent = &coordinator.ProtocolEvent{
			EventType:  coordinator.EventType(apiEvent.ProtocolEvent.Type),
			Descriptor: *getProtocolDescFromAPI(apiEvent.ProtocolEvent.Descriptor_),
		}
	}
	return event
}

func getApiEvent(event coordinator.Event) *api.Event {
	apiEvent := &api.Event{
		EventTime: timestamppb.New(event.Time),
	}
	if event.CircuitEvent != nil {
		apiEvent.CircuitEvent = &api.CircuitEvent{
			Type: api.EventType(event.CircuitEvent.EventType),
			Descriptor_: &api.ComputeSignature{
				CircuitName: event.CircuitName,
				CircuitID:   string(event.CircuitID),
			},
		}
	}
	if event.ProtocolEvent != nil {
		apiDesc := getAPIProtocolDesc(&event.ProtocolEvent.Descriptor)
		apiEvent.ProtocolEvent = &api.ProtocolEvent{Type: api.EventType(event.ProtocolEvent.EventType), Descriptor_: apiDesc}
	}
	return apiEvent
}

func readPresentFromStream(stream grpc.ClientStream) (int, error) {
	md, err := stream.Header()
	if err != nil {
		return 0, err
	}
	vals := md.Get("present")
	if len(vals) != 1 {
		return 0, fmt.Errorf("invalid stream header: present field not found")
	}

	present, err := strconv.Atoi(vals[0])
	if err != nil {
		return 0, fmt.Errorf("invalid stream header: bad value in present field: %s", vals[0])
	}
	return present, nil
}
