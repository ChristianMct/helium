// Package helium is the main entrypoint to the Helium library.
// It provides function to configure and run a Helium helper server and Helium clients.
package helium

import (
	"context"
	"net"

	"github.com/ChristianMct/helium/circuit"
	"github.com/ChristianMct/helium/node"
	"github.com/ChristianMct/helium/services/compute"
)

func RunHeliumServer(ctx context.Context, config node.Config, nl node.List, app node.App, ip compute.InputProvider) (hsv *HeliumServer, cdescs chan<- circuit.Descriptor, outs <-chan circuit.Output, err error) {

	helperNode, err := node.New(config, nl)
	if err != nil {
		return nil, nil, nil, err
	}

	hsv = NewHeliumServer(helperNode)

	lis, err := net.Listen("tcp", string(config.Address))
	if err != nil {
		return nil, nil, nil, err
	}

	go func() {
		if err := hsv.Serve(lis); err != nil {
			panic(err)
		}
	}()

	cdescs, outs, err = hsv.Run(ctx, app, ip)

	return
}

func RunHeliumClient(ctx context.Context, config node.Config, nl node.List, app node.App, ip compute.InputProvider) (hc *HeliumClient, outs <-chan circuit.Output, err error) {

	n, err := node.New(config, nl)
	if err != nil {
		return nil, nil, err
	}

	hc = NewHeliumClient(n, config.HelperID, nl.AddressOf(config.HelperID))
	if err := hc.Connect(); err != nil {
		return nil, nil, err
	}

	outs, err = hc.Run(ctx, app, ip)

	return
}
