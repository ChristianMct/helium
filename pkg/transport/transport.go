// Package transport defines an interface between the helium services and the network.
package transport

import (
	"context"
	"fmt"
	"net"

	"github.com/ldsec/helium/pkg/circuits"
	"github.com/ldsec/helium/pkg/coordinator"
	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/protocols"
	"github.com/ldsec/helium/pkg/utils"
)

// Transport is an interface for the helium transport layer abstraction.
type Transport interface {
	// Connect starts the transport. After calling Connect, the transport
	// should be running and delivering incoming/outgoing messages.
	Connect() error

	// RegisterSetupService registers the provided SetupServiceHandler as an handler for setup-
	// related queries received through the transport.
	RegisterSetupService(SetupServiceHandler)

	// RegisterComputeService registers the provided ComputeServiceHandler as an handler for compute-
	// related queries received through the transport.
	RegisterComputeService(ComputeServiceHandler)

	// GetSetupTransport returns the SetupServiceTransport instance for the
	// setup service to use.
	GetSetupTransport() SetupServiceTransport

	// GetComputeTransport returns the ComputeServiceTransport instance for the
	// compute service to use.
	GetComputeTransport() ComputeServiceTransport

	// GetNetworkStats returns the basic network-usage statistics for the transport.
	GetNetworkStats() NetStats

	// ResetNetworkStats resets the network stats
	ResetNetworkStats()
}

// SetupServiceTransport is an interface for the transport layer supporting the setup service.
type SetupServiceTransport interface {

	// RegisterForSetupAt register the caller as a node ready to perform the setup. It returns
	// a stream of protocol status updates on which it can synchronize.
	RegisterForSetupAt(context.Context, pkg.NodeID) (<-chan protocols.StatusUpdate, int, error)

	PutProtocolUpdate(protocols.StatusUpdate) (seq int, err error)

	// GetAggregationFrom queries the designated node id (typically, the aggregator) for the
	// aggregated share of the designated protocol.
	GetAggregationFrom(context.Context, pkg.NodeID, protocols.Descriptor) (*protocols.AggregationOutput, error)

	ShareTransport

	Close() // TODO: there should be a common interface for transports
}

// ComputeServiceTransport is an interface for the transport layer supporting the compute service.
type ComputeServiceTransport interface {
	RegisterForComputeAt(context.Context, pkg.NodeID) (<-chan circuits.Update, int, error)

	PutCircuitUpdates(circuits.Update) (seq int, err error)

	// GetCiphertext queries the transport for the designated ciphertext
	GetCiphertext(context.Context, pkg.CiphertextID) (*pkg.Ciphertext, error)

	// PutCiphertext sends the ciphertext over the transport.
	PutCiphertext(context.Context, pkg.NodeID, pkg.Ciphertext) error

	ShareTransport

	Close() // TODO: there should be a common interface for transports
}

type CoordinationTransport interface {
	Register(context.Context) (events <-chan coordinator.Event, present int, err error)
	Send(coordinator.Event) error
}

// ShareTransport is an interface for the transport of protocol shares.
type ShareTransport interface {
	// IncomingShares returns the channel over which the transport sends
	// incoming shares.
	IncomingShares() <-chan protocols.Share

	// OutgoingShares returns the channel over which the caller can write
	// shares for the transport to send.
	OutgoingShares() chan<- protocols.Share
}

type PeerRegisteringHandler interface {
	// Register is called by the transport when a new peer register itself for the setup.
	Register(pkg.NodeID) error

	// Unregister is called by the transport when a peer is unregistered from the setup.
	Unregister(pkg.NodeID) error
}

// SetupServiceHandler handles queries from the transport to the setup service.
type SetupServiceHandler interface {
	PeerRegisteringHandler

	// GetProtocolStatus returns the node's list of protocol along with their status.
	GetProtocolStatus() []protocols.StatusUpdate

	// GetProtocolOutput returns the aggregation output for the designated protocol
	// or an error if such output does not exist.
	GetProtocolOutput(protocols.Descriptor) (*protocols.AggregationOutput, error)
}

// ComputeServiceHandler handles queries from the transport to the compute service.
type ComputeServiceHandler interface {
	PeerRegisteringHandler

	GetCiphertext(context.Context, pkg.CiphertextID) (*pkg.Ciphertext, error)
	PutCiphertext(context.Context, pkg.Ciphertext) error
}

type Dialer = func(c context.Context, s string) (net.Conn, error)

type Peer struct {
	PeerID pkg.NodeID
}

func (p Peer) ID() pkg.NodeID {
	return p.PeerID
}

type NetStats struct {
	DataSent, DataRecv uint64
}

func (s NetStats) String() string {
	return fmt.Sprintf("Sent: %s, Received: %s", utils.ByteCountSI(s.DataSent), utils.ByteCountSI(s.DataRecv))
}
