// Package helper implements the helper-assisted setting of Helium, in which the
// parties of the MPC receive assistance from an honest-but-curious server: the
// helper aggregates every protocol, evaluates every circuit and coordinates the
// session through an event log that the peers stream.
//
// An application (see helium.App) runs on a Server (the helper node) and on a
// Client per peer node.
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
func RunServer(ctx context.Context, config Config, nl helium.NodeList, app helium.App) (hsv *Server, err error) {

	hsv, err = NewServer(config, nl)
	if err != nil {
		return nil, err
	}

	bindAddress := string(nl.AddressOf(config.ID))
	lis, err := net.Listen("tcp", bindAddress)
	if err != nil {
		return nil, err
	}
	hsv.Logf("listening on %s", bindAddress)

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
func RunClient(ctx context.Context, config Config, nl helium.NodeList, secrets helium.SecretProvider, app helium.App) (hc *Client, err error) {

	hc, err = NewClient(config, nl, secrets)
	if err != nil {
		return nil, err
	}

	if err := hc.Connect(); err != nil {
		return nil, err
	}

	log.Println("[client] running node, waiting for the helper...")
	return hc, hc.Run(ctx, app)
}
