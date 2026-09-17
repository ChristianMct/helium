// Package helper implements the helper-assisted setting of Helium, in which the
// parties of the MPC receive assistance from an honest-but-curious server: the
// helper aggregates in every protocol/evaluates in every circuit and coordinates the
// session through an event log that the peers stream.
//
// # Trust model
//
// The peers and the helper mutually authenticate with TLS (see TLSConfig).
// Identity is bound to the channel rather than to the message. This is sufficient
// in this setting because every attributed object reaches the helper directly from the
// node that produced it, over that node's own connection, and the helper aggregates
// every protocol itself.
//
// The write paths are authorized: a node can only upload shares and ciphertexts for
// itself. The read paths (GetAggregationOutput, GetCiphertext) require nothing beyond
// authentication: any node holding a certificate issued by the trusted CA can query any
// protocol's aggregation output or any operand, regardless of whether it is a
// designated receiver or even a node of the session. This is deliberate, not a gap: the
// MHE protocols are secure against a passive adversary observing the full transcript
// (aggregation and decryption shares are smudged, see protocols/adapter.go, and
// ciphertexts are semantically secure), so the transcript needs no authorization beyond
// proving the caller is a participant of the system at all.
package helper

import (
	"context"
	"log"
	"net"

	"github.com/ChristianMct/helium"
)

// RunServer creates a helper server from the config, starts serving on the helper's
// address from the node list, and runs the app on it (see Server.Run). It returns
// once the app has run, with the server (e.g., for statistics) and the error
// returned by Run.
func RunServer(ctx context.Context, config Config, app helium.App) (hsv *Server, err error) {

	hsv, err = NewServer(config)
	if err != nil {
		return nil, err
	}

	lis, err := net.Listen("tcp", string(config.Helper.NodeAddress))
	if err != nil {
		return nil, err
	}
	hsv.Logf("listening on %s", config.Helper.NodeAddress)

	go func() {
		if err := hsv.Serve(lis); err != nil {
			panic(err)
		}
	}()

	return hsv, hsv.Run(ctx, app)
}

// RunClient creates a client (peer node) from the config, connects it to the helper
// and runs the app on it (see Client.Run). It returns once the app has run, with the
// client (e.g., for statistics) and the error returned by Run.
func RunClient(ctx context.Context, config Config, secrets helium.SecretProvider, app helium.App) (hc *Client, err error) {

	hc, err = NewClient(config, secrets)
	if err != nil {
		return nil, err
	}

	if err := hc.Connect(); err != nil {
		return nil, err
	}

	log.Println("[client] running node, waiting for the helper...")
	return hc, hc.Run(ctx, app)
}
