package setup

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/protocols"
	pkg "github.com/ldsec/helium/pkg/session"
	"github.com/ldsec/helium/pkg/transport"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v4/drlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

type Service struct {
	self pkg.NodeID

	sessions  pkg.SessionProvider
	transport transport.SetupServiceTransport

	cPeers sync.Cond
	mPeers sync.RWMutex
	peers  map[pkg.NodeID]transport.Peer

	runningProtosMu sync.RWMutex
	runningProtos   map[pkg.ProtocolID]struct {
		pd       protocols.Descriptor
		incoming chan protocols.Share
	}

	completedProtoMu sync.RWMutex
	completedProto   []protocols.Descriptor

	outLock    sync.RWMutex
	aggOutputs map[pkg.ProtocolID]*protocols.AggregationOutput
}

func NewSetupService(id pkg.NodeID, sessions pkg.SessionProvider, trans transport.SetupServiceTransport) (s *Service, err error) {
	s = new(Service)

	s.self = id
	s.sessions = sessions

	s.peers = make(map[pkg.NodeID]transport.Peer)
	s.cPeers = sync.Cond{L: &s.mPeers}

	s.runningProtos = make(map[pkg.ProtocolID]struct {
		pd       protocols.Descriptor
		incoming chan protocols.Share
	})

	s.completedProto = make([]protocols.Descriptor, 0)

	s.aggOutputs = make(map[pkg.ProtocolID]*protocols.AggregationOutput)

	s.transport = trans

	return s, nil
}

// Execute executes the ProtocolFetchShareTasks of s. These tasks consist in retrieving the share from each peer in the
// protocol and aggregating the shares.
func (s *Service) Execute(sd Description, nl pkg.NodesList) error {

	log.Printf("%s | started Execute with protocols\n", s.self)

	sessID := pkg.SessionID("test-session") // TODO non-hardcoded session

	sess, exists := s.sessions.GetSessionFromID(sessID)
	if !exists {
		panic("test session does not exist")
	}

	baseProtoMap := GenProtoMap(sd, nl, sess.T, sess.Nodes, !sess.HasTSK(), false)
	aggregators := make(utils.Set[pkg.NodeID])
	pdescsMap := make(map[pkg.ProtocolID]protocols.Descriptor)

	for _, pd := range baseProtoMap {
		if pd.Aggregator != "" {
			aggregators.Add(pd.Aggregator)
		}
		pdescsMap[pd.ID] = pd
	}

	ctx := pkg.NewContext(&sessID, nil)
	outCtx := pkg.GetOutgoingContext(context.Background(), s.self)

	protocolUpdates := make(chan protocols.StatusUpdate)
	var aggDone sync.WaitGroup
	for _, agg := range aggregators.Elements() {
		agg := agg
		if agg != s.self {
			aggDone.Add(1)
			agg := agg
			go func() {
				puChan, err := s.transport.RegisterForSetupAt(outCtx, agg)
				if err == nil {
					for pd := range puChan {
						protocolUpdates <- pd
					}
					log.Printf("%s | aggregator %s done\n", s.self, agg)

				} else {
					log.Printf("%s | aggregator %s is not connected\n", s.self, agg)
				}
				aggDone.Done()
			}()
		}
	}
	go func() {
		aggDone.Wait()
		log.Printf("%s | all aggregators done\n", s.self)
		close(protocolUpdates)
	}()

	go func() {
		for incShare := range s.transport.IncomingShares() {
			s.runningProtosMu.RLock()
			proto, protoExists := s.runningProtos[incShare.ProtocolID]
			s.runningProtosMu.RUnlock()
			if !protoExists {
				panic("protocol is not running")
			}
			proto.incoming <- incShare
		}
	}()

	if baseProtoMap[0].Type == protocols.SKG && utils.NewSet(sess.Nodes).Contains(s.self) {
		var skgpd protocols.Descriptor
		skgpd, baseProtoMap = baseProtoMap[0], baseProtoMap[1:]
		proto, err := protocols.NewProtocol(skgpd, sess, skgpd.ID)
		if err != nil {
			return err
		}
		inc := make(chan protocols.Share)
		s.runningProtosMu.Lock()
		s.runningProtos[skgpd.ID] = struct {
			pd       protocols.Descriptor
			incoming chan protocols.Share
		}{skgpd, inc}
		s.runningProtosMu.Unlock()
		res := <-proto.Aggregate(ctx, sess, &ProtocolTransport{incoming: inc, outgoing: s.transport.OutgoingShares()})
		if res.Error != nil {
			return res.Error
		}
		sess.SetTSK(res.Round[0].MHEShare.(*drlwe.ShamirSecretShare))
	}

	pdescsAgg := make(chan protocols.Descriptor, len(baseProtoMap))
	if aggregators.Contains(s.self) {
		for _, pd := range baseProtoMap {
			if pd.Aggregator == s.self {
				pdescsAgg <- pd
			}
		}
	}
	close(pdescsAgg)

	outputs := make(chan struct {
		protocols.Descriptor
		protocols.Output
	})

	toRun, completed := make(chan protocols.Descriptor), make(chan protocols.Descriptor)
	go func() {
		for pu := range protocolUpdates {
			switch pu.Status {
			case protocols.OK:
				completed <- pu.Descriptor
			case protocols.Running:
				toRun <- pu.Descriptor
			}
		}
		close(toRun)
		close(completed)
	}()

	partDone := make(chan bool, 1)
	go func() {
		wgNorm := sync.WaitGroup{}
		for pdRec := range toRun {

			s.runningProtosMu.RLock()
			_, running := s.runningProtos[pdRec.ID]
			s.runningProtosMu.RUnlock()
			if running {
				continue
			}

			pd := pdescsMap[pdRec.ID]
			pd.Participants = pdRec.Participants
			proto, err := protocols.NewProtocol(pd, sess, pd.ID)
			if err != nil {
				panic(err)
			}

			inc := make(chan protocols.Share)
			s.runningProtosMu.Lock()
			s.runningProtos[pd.ID] = struct {
				pd       protocols.Descriptor
				incoming chan protocols.Share
			}{
				pd:       pd,
				incoming: inc,
			}
			s.runningProtosMu.Unlock()

			wgNorm.Add(1)
			go func() {
				<-proto.Aggregate(ctx, sess, &ProtocolTransport{incoming: inc, outgoing: s.transport.OutgoingShares()})
				wgNorm.Done()
			}()
		}
		wgNorm.Wait()
		partDone <- true
	}()

	aggsDone := make(chan bool, 1)
	go func() {
		wgAgg := sync.WaitGroup{}
		for pd := range pdescsAgg {

			switch {
			case len(pd.Participants) > 0:
			case len(pd.Participants) == 0 && sess.T < len(sess.Nodes):
				partSet := utils.NewEmptySet[pkg.NodeID]()
				if sess.Contains(s.self) {
					partSet.Add(s.self)
				}
				online, err := s.waitForRegisteredIDSet(context.Background(), sess.T-len(partSet))
				if err != nil {
					panic(err)
				}
				partSet.AddAll(online)
				pd.Participants = pkg.GetRandomClientSlice(sess.T, partSet.Elements())
			default:
				pd.Participants = make([]pkg.NodeID, len(sess.Nodes))
				copy(pd.Participants, sess.Nodes)
			}

			proto, err := protocols.NewProtocol(pd, sess, pd.ID)
			if err != nil {
				panic(err)
			}

			inc := make(chan protocols.Share)
			s.runningProtosMu.Lock()
			s.runningProtos[pd.ID] = struct {
				pd       protocols.Descriptor
				incoming chan protocols.Share
			}{
				pd:       pd,
				incoming: inc,
			}
			s.runningProtosMu.Unlock()

			s.transport.OutgoingProtocolUpdates() <- protocols.StatusUpdate{Descriptor: pd, Status: protocols.Running}

			pd := pd
			wgAgg.Add(1)
			go func() {
				aggOut := <-proto.Aggregate(ctx, sess, &ProtocolTransport{incoming: inc, outgoing: s.transport.OutgoingShares()})
				if aggOut.Error != nil {
					panic(aggOut.Error)
				}

				s.outLock.Lock()
				if _, outputExists := s.aggOutputs[pd.ID]; outputExists {
					panic("already has input for protocol")
				}
				s.aggOutputs[pd.ID] = &aggOut
				s.outLock.Unlock()

				s.completedProtoMu.Lock()
				s.completedProto = append(s.completedProto, pd)
				s.completedProtoMu.Unlock()

				s.transport.OutgoingProtocolUpdates() <- protocols.StatusUpdate{Descriptor: pd, Status: protocols.Status(api.ProtocolStatus_OK)}

				out := <-proto.Output(aggOut)

				outputs <- struct {
					protocols.Descriptor
					protocols.Output
				}{
					pd,
					out,
				}
				wgAgg.Done()
			}()

		}
		wgAgg.Wait()
		close(s.transport.OutgoingProtocolUpdates())
		aggsDone <- true
	}()

	outQueriesDone := make(chan bool, 1)
	go func() {
		for pd := range completed {
			log.Printf("%s | [%s] received aggregated completed\n", s.self, pd.ID)
			agg, err := s.transport.GetAggregationFrom(pkg.NewOutgoingContext(&s.self, &sess.ID, nil), pdescsMap[pd.ID].Aggregator, pd.ID)
			if err != nil {
				log.Printf("%s | [%s] got error on output query: %s\n", s.self, pd.ID, err)
				panic(err)
			}
			localpd := pdescsMap[pd.ID]
			var proto protocols.Instance
			proto, err = protocols.NewProtocol(localpd, sess, localpd.ID) // TODO this resamples the CRP
			if err != nil {
				panic(err)
			}
			out := <-proto.Output(*agg)

			if out.Error != nil {
				log.Printf("%s | error in protocol %s output: %v", s.self, localpd.ID, out.Error)
				continue
			}

			outputs <- struct {
				protocols.Descriptor
				protocols.Output
			}{localpd, out}
		}
		outQueriesDone <- true
	}()

	go func() {
		<-aggsDone
		log.Printf("%s | completed all aggregations\n", s.self)
		<-partDone
		log.Printf("%s | completed all participations\n", s.self)
		<-outQueriesDone
		log.Printf("%s | completed all queries\n", s.self)
		close(outputs)
	}()

	for output := range outputs {
		log.Printf("%s | got output for protocol %s\n", s.self, output.ID)

		if output.Result != nil {
			switch res := output.Result.(type) {
			case *rlwe.PublicKey:
				sess.PublicKey = res
			case *rlwe.SwitchingKey:
				err := sess.SetRotationKey(output.Args["GalEl"].(uint64), res)
				if err != nil {
					log.Printf("%s | error on output rotation key: %s", s.self, err)
				}
			case *rlwe.RelinearizationKey:
				sess.RelinearizationKey = res
			default:
				log.Printf("%s | got output for protocol %s: %v\n", s.self, output.ID, output)
			}
		}
	}

	log.Printf("%s | execute returned\n", s.self)
	return nil
}

func (s *Service) Register(peer transport.Peer) error {
	s.cPeers.L.Lock()
	if _, exists := s.peers[peer.ID()]; exists {
		return fmt.Errorf("peer with id %s already registered", peer.ID())
	}
	s.peers[peer.ID()] = peer
	s.cPeers.L.Unlock()
	s.cPeers.Broadcast()
	log.Printf("%s | peer %v registered for setup\n", s.self, peer.ID())
	// TODO unregistering
	return nil
}

func (s *Service) GetProtocolStatus() []protocols.StatusUpdate {
	s.completedProtoMu.RLock()
	s.runningProtosMu.RLock()
	comp := make([]protocols.StatusUpdate, 0, len(s.completedProto)+len(s.runningProtos))
	for _, p := range s.runningProtos {
		comp = append(comp, protocols.StatusUpdate{Descriptor: p.pd, Status: protocols.Running})
	}
	for _, pd := range s.completedProto {
		comp = append(comp, protocols.StatusUpdate{Descriptor: pd, Status: protocols.OK})
	}
	s.completedProtoMu.RUnlock()
	s.runningProtosMu.RUnlock()
	return comp
}

func (s *Service) GetProtocolOutput(pid pkg.ProtocolID) (*protocols.AggregationOutput, error) {
	s.outLock.RLock()
	defer s.outLock.RUnlock()
	out, exists := s.aggOutputs[pid]
	if !exists {
		return nil, fmt.Errorf("no input for protocol with id %s", pid)
	}
	return out, nil
}

func (s *Service) waitForRegisteredIDSet(ctx context.Context, size int) (utils.Set[pkg.NodeID], error) {
	connset := make(chan utils.Set[pkg.NodeID])
	go func() {
		s.cPeers.L.Lock()
		var connected utils.Set[pkg.NodeID]
		var err error
		for connected, err = s.registeredIDs(), ctx.Err(); len(connected) < size && err == nil; connected, err = s.registeredIDs(), ctx.Err() {
			s.cPeers.Wait()
		}
		if err == nil {
			connset <- connected
		} else {
			close(connset)
		}
		s.cPeers.L.Unlock()
	}()
	select {
	case cs := <-connset:
		return cs, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *Service) registeredIDs() utils.Set[pkg.NodeID] {
	connected := make(utils.Set[pkg.NodeID])
	for peerID := range s.peers {
		connected.Add(peerID)
	}
	return connected
}

type ProtocolTransport struct {
	incoming <-chan protocols.Share
	outgoing chan<- protocols.Share
}

func (pe *ProtocolTransport) OutgoingShares() chan<- protocols.Share {
	return pe.outgoing
}

func (pe *ProtocolTransport) IncomingShares() <-chan protocols.Share {
	return pe.incoming
}
