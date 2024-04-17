package helium

import (
	"fmt"
	"sync"

	"github.com/ChristianMct/helium/utils"
	"golang.org/x/net/context"
	"google.golang.org/grpc/stats"
)

// ServiceStats contains the network statistics of a connection.
type ServiceStats struct {
	DataSent, DataRecv uint64
}

// String returns a string representation of the network statistics.
func (s ServiceStats) String() string {
	return fmt.Sprintf("Sent: %s, Received: %s", utils.ByteCountSI(s.DataSent), utils.ByteCountSI(s.DataRecv))
}

type NetStats struct {
	Setup, Compute, Others ServiceStats
}

func (ns NetStats) String() string {
	return fmt.Sprintf("NetStats:\n\tSetup: %s\n\tCompute: %s\n\tOthers: %s", ns.Setup, ns.Compute, ns.Others)
}

type statsHandler struct {
	mu sync.Mutex
	NetStats
}

// TagRPC can attach some information to the given context.
// The context used for the rest lifetime of the RPC will be derived from
// the returned context.
func (s *statsHandler) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context {
	service := valueFromIncomingContext(ctx, "service") // TODO: should do all incoming context tagging here...
	if service != "" {
		ctx = context.WithValue(ctx, "service", service)
	}
	return ctx
}

// HandleRPC processes the RPC stats.
func (s *statsHandler) HandleRPC(ctx context.Context, sta stats.RPCStats) {

	var ns *ServiceStats
	phase := ctx.Value("service")
	switch phase {
	case "setup":
		ns = &s.Setup
	case "compute":
		ns = &s.Compute
	default:
		ns = &s.Others
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	switch sta := sta.(type) {
	case *stats.InPayload:
		ns.DataRecv += uint64(sta.WireLength)
	case *stats.OutPayload:
		ns.DataSent += uint64(sta.WireLength)
	}
}

// TagConn can attach some information to the given context.
// The returned context will be used for stats handling.
// For conn stats handling, the context used in HandleConn for this
// connection will be derived from the context returned.
// For RPC stats handling,
//   - On server side, the context used in HandleRPC for all RPCs on this
//     connection will be derived from the context returned.
//   - On client side, the context is not derived from the context returned.
func (s *statsHandler) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	service := valueFromIncomingContext(ctx, "service")
	if service != "" {
		ctx = context.WithValue(ctx, "service", service)
	}
	return ctx
}

// HandleConn processes the Conn stats.
func (s *statsHandler) HandleConn(_ context.Context, sta stats.ConnStats) {}

func (s *statsHandler) GetStats() NetStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.NetStats
}

// func (node *Node) GetNetworkStats() centralized.NetStats {
// 	var stats, srvStats, cliStats centralized.NetStats
// 	if node.srv != nil {
// 		srvStats = node.srv.GetStats()
// 		stats.DataRecv += srvStats.DataRecv
// 		stats.DataSent += srvStats.DataSent
// 	}
// 	if node.cli != nil {
// 		cliStats = node.cli.GetStats()
// 		stats.DataRecv += cliStats.DataRecv
// 		stats.DataSent += cliStats.DataSent
// 	}
// 	return stats
// }

// // outputStats outputs the total network usage and time take to execute a protocol phase.
// func (node *Node) OutputStats(phase string, elapsed time.Duration, write bool, metadata ...map[string]string) {

// 	dataSent := node.GetTransport().GetNetworkStats().DataSent
// 	dataRecv := node.GetTransport().GetNetworkStats().DataRecv
// 	fmt.Printf("STATS: phase: %s time: %f sent: %f MB recv: %f MB\n", phase, elapsed.Seconds(), float64(dataSent)/float64(1e6), float64(dataRecv)/float64(1e6))
// 	log.Println("==============", phase, "phase ==============")
// 	log.Printf("%s | time %s", node.ID(), elapsed)
// 	log.Printf("%s | network: %s\n", node.ID(), node.GetTransport().GetNetworkStats())
// 	if write {
// 		stats := map[string]string{
// 			"Wall":  fmt.Sprint(elapsed),
// 			"Sent":  fmt.Sprint(dataSent),
// 			"Recvt": fmt.Sprint(dataRecv),
// 			"ID":    fmt.Sprint(node.ID()),
// 			"Phase": phase,
// 		}
// 		for _, md := range metadata {
// 			for k, v := range md {
// 				stats[k] = v
// 			}
// 		}
// 		var statsJSON []byte
// 		statsJSON, err := json.MarshalIndent(stats, "", "\t")
// 		if err != nil {
// 			panic(err)
// 		}
// 		if errWrite := os.WriteFile(fmt.Sprintf("/helium/stats/%s-%s.json", phase, node.ID()), statsJSON, 0600); errWrite != nil {
// 			log.Println(errWrite)
// 		}
// 	}
// }

// func (node *Node) ResetNetworkStats() {
// 	node.transport.ResetNetworkStats()
// }
