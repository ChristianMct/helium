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
	completedProtos  []protocols.Descriptor

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

	s.completedProtos = make([]protocols.Descriptor, 0)

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

	// 1. INITIALIZATION: generate the list of protocols to execute
	doThresholdSetup := !sess.HasTSK()
	// From setup descriptor and session, generate a list of protocols to execute.
	// list of protocols descriptors.
	// if the result for a protocol is already in the key-store, than that protocol is
	protoIDtoPD := GenProtoMap(sd, nl, sess.T, sess.Nodes, doThresholdSetup, false)

	// set of nodes that aggregate (for at least one protocol).
	aggregators := make(utils.Set[pkg.NodeID])
	for _, pd := range protoIDtoPD {
		if pd.Aggregator != "" {
			aggregators.Add(pd.Aggregator)
		}
	}

	// keep track of protocols whose results are already available
	protoIDtoResultPresent := s.checkObjectStore(protoIDtoPD, sess)

	ctx := pkg.NewContext(&sessID, nil)
	outCtx := pkg.GetOutgoingContext(context.Background(), s.self)

	// 2. REGISTRATION: register for setup to the aggregator
	protosUpdatesChan := s.registerToAggregatorsForSetup(&aggregators, outCtx)

	// split protocols updates into to run and completed.
	protoToRun, protoCompleted := make(chan protocols.Descriptor), make(chan protocols.Descriptor)
	go func() {
		// every time it receives a protocol update, puts the protocol descriptor
		// in the protocols to run or in the protocols completed
		for protoUpdate := range protosUpdatesChan {
			switch protoUpdate.Status {
			case protocols.OK:
				protoCompleted <- protoUpdate.Descriptor
			case protocols.Running:
				protoToRun <- protoUpdate.Descriptor
			}
		}
		// no more updates from any protocol.
		close(protoToRun)
		close(protoCompleted)
	}()

	// get incoming shares and put them into proto.incoming.
	go func() {
		for incShare := range s.transport.IncomingShares() {
			s.runningProtosMu.RLock()
			proto, protoExists := s.runningProtos[incShare.ProtocolID]
			s.runningProtosMu.RUnlock()
			if !protoExists {
				panic("protocol is not running")
			}
			// sends received share to the incoming channel of the destination protocol.
			proto.incoming <- incShare
		}
	}()

	// if first protocol to execute is SKG and this node is part of the session nodes.
	// execute aggregation to set share of SK T-out-of-N.
	skgpd, skgPDexists := protoIDtoPD[pkg.ProtocolID(protocols.SKG.String())]
	if skgPDexists && utils.NewSet(sess.Nodes).Contains(s.self) {
		// if !ok {
		// 	return fmt.Errorf("%s | Threshold Setup is enabled but there is no SKG protocol to execute", s.self)
		// }
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

	pdAggs := make(chan protocols.Descriptor, len(protoIDtoPD))
	// if the current node is an aggregator.
	if aggregators.Contains(s.self) {
		for _, pd := range protoIDtoPD {
			// if the current node is the aggregator for the current protocol.
			if pd.Aggregator == s.self {
				// send the protoDescr to the channel transporting the protoDescr of the aggregators.
				pdAggs <- pd
			}
		}
	}
	close(pdAggs)

	// 3A PARTICIPATION: node participate to protocols if they are in the list of participants
	allPartsDone := s.participate(protoToRun, protoIDtoPD, sess, ctx, protoIDtoResultPresent)

	// 3B AGGREGATION: aggregators wait for T parties, then aggregate the shares into an output, and update the parties.
	// channel that transports outputs for each protocol.
	outputs := make(chan struct {
		protocols.Descriptor
		protocols.Output
	})
	allAggsDone := s.aggregate(pdAggs, outputs, ctx, sess, protoIDtoResultPresent)

	// 4. FINALIZE: query completed protocols for output
	outQueriesDone := s.queryForOutput(protoCompleted, protoIDtoPD, sess, outputs, protoIDtoResultPresent)

	// close the output channel and print status.
	go func() {
		<-allAggsDone
		log.Printf("%s | completed all aggregations\n", s.self)
		<-allPartsDone
		log.Printf("%s | completed all participations\n", s.self)
		<-outQueriesDone
		log.Printf("%s | completed all queries\n", s.self)
		close(outputs) // close output channel, no more values will be sent through it.
	}()

	// 5. STORE OUTPUT: store output after receiving it from the aggregator
	s.storeProtocolOutput(outputs, sess)

	log.Printf("%s | execute returned\n", s.self)
	return nil
}

func (s *Service) checkObjectStore(protoIDtoPD ProtocolMap, sess *pkg.Session) map[pkg.ProtocolID]bool {
	protoIDtoResultPresent := make(map[pkg.ProtocolID]bool)

	for id, pd := range protoIDtoPD {
		present, err := sess.ObjectStore.IsPresent(string(pd.ID))
		// DEBUG
		log.Printf("%s | [CheckObjectStore] IsPresent of %s returned %v", s.self, pd.ID, present)
		if err != nil {
			panic(err)
		}
		protoIDtoResultPresent[id] = present
	}

	return protoIDtoResultPresent
}

// registerToAggregatorsForSetup registers the caller to all the aggregators and returns a channel where protocols updates are sent.
func (s *Service) registerToAggregatorsForSetup(aggregators *utils.Set[pkg.NodeID], outCtx context.Context) <-chan protocols.StatusUpdate {
	// channel that carries protocol updates (for all protocols).
	protosUpdatesChan := make(chan protocols.StatusUpdate)
	var aggDone sync.WaitGroup
	for _, agg := range aggregators.Elements() {
		agg := agg
		// does not register to itself.
		if agg == s.self {
			continue
		}
		aggDone.Add(1)
		go func() {
			// DEBUG
			log.Printf("%s | registering to aggregator %s\n", s.self, agg)
			// END DEBUG
			// register aggregator to the transport for the setup protocol.
			protoUpdateChannel, err := s.transport.RegisterForSetupAt(outCtx, agg)
			if err != nil {
				log.Printf("%s | could not register to aggregator %s: %s\n", s.self, agg, err)
				aggDone.Done()
				return
			}
			// for each update of this protocol from the aggregator.
			for protoStatusUpdate := range protoUpdateChannel {
				// put the update in the update channel for ALL protocols.
				protosUpdatesChan <- protoStatusUpdate
			}
			// no more updates from this aggregator.
			log.Printf("%s | aggregator %s done\n", s.self, agg)

			aggDone.Done()
		}()
	}

	// this routine waits until all aggregators have been registered.
	go func() {
		// when all aggregators have been registered and have no more updates.
		aggDone.Wait()
		log.Printf("%s | registration to all aggregators done\n", s.self)
		// close the global update channels, others will know that no more updates are coming.
		close(protosUpdatesChan)
	}()

	return protosUpdatesChan
}

// participate makes every participant participate in the protocol
// returns a channel where true is sent when all participations are done.
func (s *Service) participate(protoToRun chan protocols.Descriptor, protoIDtoPD ProtocolMap, sess *pkg.Session, ctx context.Context, protoIDtoResultPresent PresenceMap) <-chan bool {
	// allPartsDone is a channel that transport the signal that the participations are done.
	allPartsDone := make(chan bool, 1)
	go func() {
		wgNorm := sync.WaitGroup{}
		for pd := range protoToRun {

			present, ok := protoIDtoResultPresent[pd.ID]
			if !ok {
				panic(fmt.Errorf("%s | [Participate] Error: Protocol ID is not present in the ResultPresent map pd: %v\n", s.self, pd))
			}
			if present {
				log.Printf("%s | [Participate] Skipping, result already present for pd: %v\n", s.self, pd)
				continue
			}

			s.runningProtosMu.RLock()
			_, running := s.runningProtos[pd.ID]
			s.runningProtosMu.RUnlock()
			// already running, next pd.
			if running {
				continue
			}

			newpd := protoIDtoPD[pd.ID]
			newpd.Participants = pd.Participants
			// DEBUG
			log.Printf("%s | [Participate] Making new protocol pd: %v\n", s.self, newpd)
			// END DEBUG
			proto, err := protocols.NewProtocol(newpd, sess, newpd.ID)
			if err != nil {
				panic(err)
			}

			inc := make(chan protocols.Share)
			// add protocols to running protocols
			s.runningProtosMu.Lock()
			s.runningProtos[newpd.ID] = struct {
				pd       protocols.Descriptor
				incoming chan protocols.Share
			}{
				pd:       newpd,
				incoming: inc,
			}
			s.runningProtosMu.Unlock()

			wgNorm.Add(1)
			//DEBUG
			log.Printf("%s | [Participate] Adding a goroutine to wait for pd: %v\n", s.self, newpd)
			go func() {
				// wait for the result of the aggregation to arrive
				<-proto.Aggregate(ctx, sess, &ProtocolTransport{incoming: inc, outgoing: s.transport.OutgoingShares()})
				//DEBUG
				log.Printf("%s | [Participate] Removing a goroutine to wait for pd: %v\n", s.self, newpd)
				wgNorm.Done()
			}()
		}
		wgNorm.Wait()
		allPartsDone <- true
	}()

	return allPartsDone
}

func (s *Service) aggregate(pdAggs chan protocols.Descriptor, outputs chan struct {
	protocols.Descriptor
	protocols.Output
}, ctx context.Context, sess *pkg.Session, protoIDtoResultPresent PresenceMap) <-chan bool {
	allAggsDone := make(chan bool, 1)
	go func() {
		wgAgg := sync.WaitGroup{}
		// for every protocol for which the current node is aggregator
		for pd := range pdAggs {

			present, ok := protoIDtoResultPresent[pd.ID]
			if !ok {
				panic(fmt.Errorf("%s | [Aggregate] Protocol ID is not present in the ResultPresent map pd: %v\n", s.self, pd))
			}
			if present {
				// DEBUG
				log.Printf("%s | [Aggregate] Skipping, result already present for pd: %v\n", s.self, pd)
				continue
			}

			// select participants for this aggregation
			switch {
			case len(pd.Participants) > 0:
			// select a subset of T participants
			case len(pd.Participants) == 0 && sess.T < len(sess.Nodes):
				partSet := utils.NewEmptySet[pkg.NodeID]()
				if sess.Contains(s.self) {
					partSet.Add(s.self)
				}
				// Wait for at least T parties to connect
				online, err := s.waitForRegisteredIDSet(context.Background(), sess.T-len(partSet))
				if err != nil {
					panic(err)
				}
				partSet.AddAll(online)
				// select T parties at random
				pd.Participants = pkg.GetRandomClientSlice(sess.T, partSet.Elements())
			// default puts all the nodes in the participant list of the protocol
			default:
				pd.Participants = make([]pkg.NodeID, len(sess.Nodes))
				copy(pd.Participants, sess.Nodes)
			}

			// DEBUG
			log.Printf("%s | [Aggregate] Making new protocol pd: %v\n", s.self, pd)
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

			// sending pd to list of chosen parties.
			s.transport.OutgoingProtocolUpdates() <- protocols.StatusUpdate{Descriptor: pd, Status: protocols.Running}

			pd := pd
			wgAgg.Add(1)
			go func() {
				// blocking, returns the result of the aggregation.
				aggOut := <-proto.Aggregate(ctx, sess, &ProtocolTransport{incoming: inc, outgoing: s.transport.OutgoingShares()})
				if aggOut.Error != nil {
					panic(aggOut.Error)
				}

				s.saveAggOut(aggOut, pd, proto, outputs)

				wgAgg.Done()
			}()

		}
		wgAgg.Wait()
		close(s.transport.OutgoingProtocolUpdates())
		allAggsDone <- true
	}()
	return allAggsDone
}

func (s *Service) saveAggOut(aggOut protocols.AggregationOutput,
	pd protocols.Descriptor,
	proto protocols.Instance,
	outputs chan struct {
		protocols.Descriptor
		protocols.Output
	}) {

	s.outLock.Lock()
	if _, outputExists := s.aggOutputs[pd.ID]; outputExists {
		panic("already has input for protocol")
	}
	s.aggOutputs[pd.ID] = &aggOut
	s.outLock.Unlock()

	s.completedProtoMu.Lock()
	s.completedProtos = append(s.completedProtos, pd)
	s.completedProtoMu.Unlock()

	s.transport.OutgoingProtocolUpdates() <- protocols.StatusUpdate{Descriptor: pd, Status: protocols.Status(api.ProtocolStatus_OK)}

	// block until it gets a value from the channel
	out := <-proto.Output(aggOut)

	outputs <- struct {
		protocols.Descriptor
		protocols.Output
	}{
		pd,
		out,
	}
}

// queryForOutput accepts a channel where to send outputs
// and returns a channel `outQueriesDone` where true will be sent when all the outputs for a protocol.
func (s *Service) queryForOutput(protoCompleted <-chan protocols.Descriptor, protoIDtoProtoDescr ProtocolMap, sess *pkg.Session, outputs chan<- struct {
	protocols.Descriptor
	protocols.Output
}, protoIDtoResultPresent PresenceMap) <-chan bool {
	outQueriesDone := make(chan bool, 1)
	go func() {
		// every completed protocol yields a result.
		for pd := range protoCompleted {
			log.Printf("%s | [QueryForOutput] [%s] received aggregated completed\n", s.self, pd.ID)

			present, ok := protoIDtoResultPresent[pd.ID]
			if !ok {
				panic(fmt.Errorf("%s | [QueryForOutput] Protocol ID is not present in the ResultPresent map pd: %v\n", s.self, pd))
			}
			if present {
				log.Printf("%s | [QueryForOutput] Skipping, result already present for pd: %v\n", s.self, pd.ID)

				continue
			}

			// requests output to aggregator.
			aggregatedOutput, err := s.transport.GetAggregationFrom(pkg.NewOutgoingContext(&s.self, &sess.ID, nil), protoIDtoProtoDescr[pd.ID].Aggregator, pd.ID)
			if err != nil {
				log.Printf("%s | [QueryForOutput] [%s] got error on output query: %s\n", s.self, pd.ID, err)
				panic(err)
			}
			localpd := protoIDtoProtoDescr[pd.ID]
			var proto protocols.Instance
			// DEBUG
			log.Printf("%s | [QueryForOutput] Making new protocol pd: %v\n", s.self, localpd)
			// END DEBUG
			proto, err = protocols.NewProtocol(localpd, sess, localpd.ID) // TODO this resamples the CRP
			if err != nil {
				panic(err)
			}
			out := <-proto.Output(*aggregatedOutput)

			if out.Error != nil {
				log.Printf("%s | [QueryForOutput] Error in protocol %s output: %v", s.self, localpd.ID, out.Error)
				continue
			}

			outputs <- struct {
				protocols.Descriptor
				protocols.Output
			}{localpd, out}
		}
		outQueriesDone <- true
	}()

	return outQueriesDone
}

func (s *Service) storeProtocolOutput(outputs chan struct {
	protocols.Descriptor
	protocols.Output
}, sess *pkg.Session) {
	for output := range outputs {
		log.Printf("%s | got output for protocol %s\n", s.self, output.ID)

		if output.Result != nil {
			switch res := output.Result.(type) {
			case *rlwe.PublicKey:
				log.Printf("%s | [StoreOutput]: storing CPK under %s %v\n", s.self, output.ID, res)
				err := sess.ObjectStore.Store(string(output.ID), res)
				if err != nil {
					log.Printf("%s | error on Collective Public Key store: %s", s.self, err)
				}
			case *rlwe.SwitchingKey:
				log.Printf("%s | [StoreOutput]: storing RTG under %s %v\n", s.self, output.ID, res)
				err := sess.ObjectStore.Store(string(output.ID), res)
				if err != nil {
					log.Printf("%s | error on Rotation Key Store: %s", s.self, err)
				}
			case *rlwe.RelinearizationKey:
				log.Printf("%s | [StoreOutput]: storing RLK under %s %v\n", s.self, output.Type.ProtoID(), res)
				err := sess.ObjectStore.Store(string(output.ID), res)
				if err != nil {
					log.Printf("%s | error on Relinearization Key store: %s", s.self, err)
				}
			default:
				log.Printf("%s | got output for protocol %s: %v\n", s.self, output.ID, output)
			}
		}
	}
}

func (s *Service) Register(peer transport.Peer) error {
	s.cPeers.L.Lock()
	if _, exists := s.peers[peer.ID()]; exists {
		// return fmt.Errorf("peer with id %s already registered", peer.ID())
		log.Printf("%s | peer %s was already registered", s.self, peer.ID())
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
	comp := make([]protocols.StatusUpdate, 0, len(s.completedProtos)+len(s.runningProtos))
	for _, p := range s.runningProtos {
		comp = append(comp, protocols.StatusUpdate{Descriptor: p.pd, Status: protocols.Running})
	}
	for _, pd := range s.completedProtos {
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
