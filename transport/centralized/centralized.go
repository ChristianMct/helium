// Package centralized defines a client-server-based transport for the helium services.
// This transport is based on gRPC services.
package centralized

import (
	"context"
	"fmt"
	"net"

	"github.com/ChristianMct/helium/utils"
)

// Dialer is a function that returns a net.Conn to the provided address.
type Dialer = func(c context.Context, addr string) (net.Conn, error)

// NetStats contains the network statistics of a connection.
type NetStats struct {
	DataSent, DataRecv uint64
}

// String returns a string representation of the network statistics.
func (s NetStats) String() string {
	return fmt.Sprintf("Sent: %s, Received: %s", utils.ByteCountSI(s.DataSent), utils.ByteCountSI(s.DataRecv))
}
