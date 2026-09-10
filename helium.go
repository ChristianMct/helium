// Package helium is the main entrypoint to the Helium library.
// It provides function to configure and run a Helium helper server and Helium clients.
package helium

import (
	"context"
	"log"
	"net"

	"github.com/ChristianMct/helium/circuits"
)

// RunHeliumServer creates a helium server (helper node) from the config, starts serving on
// the helper's address from the node list, and runs the app on it (see HeliumServer.Run).
func RunHeliumServer(ctx context.Context, config Config, nl List, app App, ip circuits.InputProvider) (hsv *HeliumServer, err error) {

	hsv, err = NewHeliumServer(config, nl)
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

	if err := hsv.Run(ctx, app, ip); err != nil {
		return nil, err
	}
	return hsv, nil
}

// RunHeliumClient creates a helium client (peer node) from the config, connects it to the
// helper and runs the app on it (see HeliumClient.Run).
func RunHeliumClient(ctx context.Context, config Config, nl List, secrets SecretProvider, app App, ip circuits.InputProvider) (hc *HeliumClient, err error) {

	hc, err = NewHeliumClient(config, nl, secrets)
	if err != nil {
		return nil, err
	}

	log.Println("[client] connecting to helper...")
	if err := hc.Connect(); err != nil {
		return nil, err
	}

	log.Println("[client] running node")
	if err := hc.Run(ctx, app, ip); err != nil {
		return nil, err
	}
	return hc, nil
}
