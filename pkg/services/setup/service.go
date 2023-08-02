package setup

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/ldsec/helium/pkg"
	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/protocols"
	"github.com/ldsec/helium/pkg/transport"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v4/drlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

const parallelAggregation int = 10
const parallelParticipation int = 10

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

	*drlwe.Combiner
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

	s.Logf("started Execute")

	sessID := pkg.SessionID("test-session") // TODO non-hardcoded session

	sess, exists := s.sessions.GetSessionFromID(sessID)
	if !exists {
		panic("test session does not exist")
	}

	// 1. INITIALIZATION: generate the list of protocols signatures to execute and relative receivers
	sigList, sigToReceiverSet := DescriptionToSignatureList(sd)

	// keep track of protocols whose results are already available
	sigListNoResult, _ := s.filterSignatureList(sigList, sess)

	// set of full nodes (that might be aggregators/helpers)
	aggregators := make(utils.Set[pkg.NodeID])
	for _, node := range nl {
		if node.NodeAddress != "" {
			aggregators.Add(node.NodeID)
		}
	}

	// 2. REGISTRATION: register for setup to the aggregator
	ctx := pkg.NewContext(&sessID, nil)
	outCtx := pkg.GetOutgoingContext(context.Background(), s.self)
	protosUpdatesChan := s.registerToAggregatorsForSetup(&aggregators, outCtx)

	// split protocols updates into to run and completed.
	protoToRun, protoCompleted := make(chan protocols.Descriptor), make(chan protocols.Descriptor)
	go func() {
		// every time it receives a protocol update, puts the protocol descriptor
		// in the protocols to run or in the protocols completed
		for protoUpdate := range protosUpdatesChan {
			s.Logf("got protocol update for protocol %s : status: %v ", protoUpdate.HID(), protoUpdate.Status)
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
				s.Logf("dropped share from sender %s: protocol %s is not running", incShare.From, incShare.ProtocolID)
				continue
			}
			// sends received share to the incoming channel of the destination protocol.
			proto.incoming <- incShare
			//s.Logf("received share from sender %s for protocol %s", incShare.From, incShare.ProtocolID)
		}
	}()

	// 3A PARTICIPATION: node participate to protocols if they are in the list of participants
	allPartsDone := s.participate(ctx, sigListNoResult, protoToRun, sess)

	// 3B AGGREGATION: aggregators wait for T parties, then aggregate the shares into an output, and update the parties.
	// channel that transports outputs for each protocol.
	outputs := make(chan struct {
		protocols.Descriptor
		protocols.Output
	})
	var allAggsDone <-chan bool
	if aggregators.Contains(s.self) {
		allAggsDone = s.aggregate(ctx, sigListNoResult, outputs, sess)
	} else {
		nop := make(chan bool)
		close(nop)
		allAggsDone = nop
	}

	// 4. FINALIZE: query completed protocols for output
	outQueriesDone := s.queryForOutput(ctx, sigListNoResult, sigToReceiverSet, protoCompleted, sess, outputs)

	// close the output channel and print status.
	go func() {
		<-allAggsDone
		s.Logf("completed all aggregations")
		<-allPartsDone
		s.Logf("completed all participations")
		<-outQueriesDone
		s.Logf("completed all queries")
		close(outputs) // close output channel, no more values will be sent through it.
	}()

	// 5. STORE OUTPUT: store output after receiving it from the aggregator
	s.storeProtocolOutput(outputs, sess)

	s.Logf("execute returned")
	return nil
}

// filterSignatureList splits a SignatureList into two lists based on the presence of the protocol's output in the ObjectStore.
func (s *Service) filterSignatureList(sl SignatureList, sess *pkg.Session) (noResult, hasResult SignatureList) {
	noResult, hasResult = make(SignatureList, 0), make(SignatureList, 0)
	for _, sig := range sl {
		has, err := sess.ObjectStore.IsPresent(sig.String())
		if err != nil {
			panic(err)
		}
		if has {
			hasResult = append(hasResult, sig)
		} else {
			noResult = append(noResult, sig)
		}
	}
	return
}

// registerToAggregatorsForSetup registers the caller to all the aggregator.
// Returns a channel where protocols updates are sent.
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
			s.Logf("[Register] registering to aggregator %s", agg)
			// register aggregator to the transport for the setup protocol.
			protoUpdateChannel, err := s.transport.RegisterForSetupAt(outCtx, agg)
			if err != nil {
				s.Logf("could not register to aggregator %s: %s", agg, err)
				aggDone.Done()
				return
			}
			// for each update of this protocol from the aggregator.
			for protoStatusUpdate := range protoUpdateChannel {
				// put the update in the update channel for ALL protocols.
				protosUpdatesChan <- protoStatusUpdate
			}
			// no more updates from this aggregator.
			s.Logf("[Register] aggregator %s done", agg)

			aggDone.Done()
		}()
	}

	// this routine waits until all aggregators have been registered.
	go func() {
		// when all aggregators have been registered and have no more updates.
		aggDone.Wait()
		s.Logf("[Register] registration to all aggregators done")
		// close the global update channels, others will know that no more updates are coming.
		close(protosUpdatesChan)
	}()

	return protosUpdatesChan
}

// participate makes every participant participate in the protocol.
// Returns a channel where true is sent when all participations are done.
func (s *Service) participate(ctx context.Context, sigList SignatureList, protoToRun chan protocols.Descriptor, sess *pkg.Session) <-chan bool {

	var wg sync.WaitGroup
	for w := 0; w < parallelParticipation; w++ {
		wg.Add(1)
		go func() {
			for pd := range protoToRun {

				pid := pd.ID()

				if !sigList.Contains(pd.Signature) {
					panic(fmt.Errorf("error: protocol descriptor %s signature %s is not in the signature list", pd, pd.Signature))
				}

				s.runningProtosMu.Lock()
				_, running := s.runningProtos[pid]
				// already running, next pd.
				if running {
					s.runningProtosMu.Unlock()
					continue
				}

				// add protocols to running protocols
				inc := make(chan protocols.Share)
				s.runningProtos[pid] = struct {
					pd       protocols.Descriptor
					incoming chan protocols.Share
				}{
					pd:       pd,
					incoming: inc,
				}
				s.runningProtosMu.Unlock()

				// DEBUG
				s.Logf("[Participate] Making new protocol pd: %v", pd)
				proto, err := protocols.NewProtocol(pd, sess)
				if err != nil {
					panic(err)
				}

				var ctxdl context.Context
				if sess.T != len(sess.Nodes) {
					ctxdl, _ = context.WithTimeout(ctx, 10*time.Second)
				} else {
					ctxdl = ctx
				}

				if pd.Signature.Type == protocols.RKG_2 {
					aggregatedOutput, err := s.transport.GetAggregationFrom(pkg.NewOutgoingContext(&s.self, &sess.ID, nil), pd.Aggregator, protocols.Descriptor{Signature: protocols.Signature{Type: protocols.RKG_1}, Participants: pd.Participants}.ID())
					if err != nil {
						s.Logf("[participate] [%s] got error on output query: %s", pid, err)
						panic(err)
					}
					go func() {
						inc <- aggregatedOutput.Round[0]
					}()
				}

				aggOut := <-proto.Aggregate(ctxdl, &ProtocolTransport{incoming: inc, outgoing: s.transport.OutgoingShares()})
				if aggOut.Error != nil {
					//panic(aggOut.Error)
					log.Println(aggOut.Error)
				}
			}
			wg.Done()
		}()
	}

	// allPartsDone is a channel that transport the signal that the participations are done.
	allPartsDone := make(chan bool, 1)
	go func() {
		wg.Wait()
		allPartsDone <- true
	}()

	return allPartsDone
}

// aggregate makes every aggregator aggregate the shares for the required protocols.
// Returns a channel where true is sent when all aggregations are done.
func (s *Service) aggregate(ctx context.Context, sigList SignatureList, outputs chan struct {
	protocols.Descriptor
	protocols.Output
}, sess *pkg.Session) <-chan bool {

	// if the current node is an aggregator, create a protocol description
	// for each signature to run, with itself as aggregator and undefined plist.
	// TODO: assumes all aggregators run the required protocol
	pdAggs := make(chan protocols.Descriptor, len(sigList))
	wgSig := sync.WaitGroup{}
	wgSig.Add(len(sigList))
	for _, sig := range sigList {
		if sig.Type != protocols.RKG_2 {
			pdAggs <- protocols.Descriptor{Signature: sig, Aggregator: s.self}
		}
	}

	go func() {
		wgSig.Wait()
		close(pdAggs)
	}()

	var currRlkShare protocols.Share

	var wg sync.WaitGroup
	for w := 0; w < parallelAggregation; w++ {
		wg.Add(1)
		go func() {
			// for every protocol for which the current node is aggregator
			for pd := range pdAggs { // TODO NEXT: this could be a priority queue of struct{Descriptor, Context} and retries are simply a new Descriptor with higher priority (the first protocol to succeed cancels the context)

				// select participants for this aggregation
				switch {
				case len(pd.Participants) > 0:

				// CASE T < N
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
					//pd.Participants = pkg.GetRandomClientSlice(sess.T, sess.Nodes) // Fault injection

				// CASE N
				default:
					// for the PK subprotocol, the participants sets is different
					if pd.Signature.Type == protocols.PK {
						// participant is the sender of the pk
						pd.Participants = []pkg.NodeID{pkg.NodeID(pd.Signature.Args["Sender"])}
					} else {
						pd.Participants = make([]pkg.NodeID, len(sess.Nodes))
						copy(pd.Participants, sess.Nodes)
					}
				}

				s.Logf("[Aggregate] Making new protocol pd: %v", pd)
				proto, err := protocols.NewProtocol(pd, sess)
				if err != nil {
					panic(err)
				}

				pid := pd.ID()
				inc := make(chan protocols.Share)
				s.runningProtosMu.Lock()
				s.runningProtos[pid] = struct {
					pd       protocols.Descriptor
					incoming chan protocols.Share
				}{
					pd:       pd,
					incoming: inc,
				}
				s.runningProtosMu.Unlock()

				// sending pd to list of chosen parties.
				s.transport.OutgoingProtocolUpdates() <- protocols.StatusUpdate{Descriptor: pd, Status: protocols.Running}

				// blocking, returns the result of the aggregation.
				s.Logf("[Aggregate] Waiting to finish aggregation for pd: %v", pd)

				var ctxdl context.Context
				if sess.T != len(sess.Nodes) {
					var timeout time.Duration
					if proto.Desc().Signature.Type == protocols.RKG_1 {
						timeout = 3 * time.Second
					} else {
						timeout = 10 * time.Second
					}
					ctxdl, _ = context.WithTimeout(ctx, timeout)
				} else {
					ctxdl = ctx
				}

				if pd.Signature.Type == protocols.RKG_2 {
					go func() {
						inc <- currRlkShare
					}()
				}

				// s.Logf("[Aggregate] Service is %v", s)
				aggOut := <-proto.Aggregate(ctxdl, &ProtocolTransport{incoming: inc, outgoing: s.transport.OutgoingShares()})
				if aggOut.Error != nil {
					//panic(aggOut.Error)
					log.Println(aggOut.Error)
					pdAggs <- protocols.Descriptor{Signature: pd.Signature, Aggregator: s.self}
					s.runningProtosMu.Lock()
					delete(s.runningProtos, pid)
					s.runningProtosMu.Unlock()
					continue
				}
				s.Logf("[Aggregate] Finished aggregating for pd: %v", pd)

				s.saveAggOut(aggOut, pd, proto, outputs)

				s.runningProtosMu.Lock()
				delete(s.runningProtos, pid)
				s.runningProtosMu.Unlock()

				s.completedProtoMu.Lock()
				s.completedProtos = append(s.completedProtos, pd)
				s.completedProtoMu.Unlock()

				s.transport.OutgoingProtocolUpdates() <- protocols.StatusUpdate{Descriptor: pd, Status: protocols.Status(api.ProtocolStatus_OK)}

				if pd.Signature.Type == protocols.RKG_1 {
					currRlkShare = aggOut.Round[0]
					pdAggs <- protocols.Descriptor{Signature: protocols.Signature{Type: protocols.RKG_2}, Participants: pd.Participants, Aggregator: s.self}
				}

				if pd.Signature.Type == protocols.RKG_2 {
					aggOut.Round = []protocols.Share{currRlkShare, aggOut.Round[0]}
				}

				// block until it gets a value from the channel
				out := <-proto.Output(aggOut)
				if out.Error != nil {
					s.Logf("Error in protocol %s output: %v", pid, out.Error)
				}

				outputs <- struct {
					protocols.Descriptor
					protocols.Output
				}{
					pd,
					out,
				}

				wgSig.Done()
			}
			wg.Done()
		}()
	}

	allAggsDone := make(chan bool, 1)
	go func() {
		wg.Wait()
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
	pid := pd.ID()
	s.outLock.Lock()
	if _, outputExists := s.aggOutputs[pid]; outputExists {
		panic("already has input for protocol")
	}
	s.aggOutputs[pid] = &aggOut
	s.outLock.Unlock()
}

// queryForOutput makes participants of a protocol query the cloud for that protocol's output.
// Returns a channel where true is sent when all queries are done.
func (s *Service) queryForOutput(ctx context.Context, sigListNoResult SignatureList, sigToReceiverSet ReceiversMap, protoCompleted <-chan protocols.Descriptor, sess *pkg.Session, outputs chan<- struct {
	protocols.Descriptor
	protocols.Output
}) <-chan bool {

	outQueriesDone := make(chan bool, 1)
	go func() {
		// every completed protocol yields a result.
		for pd := range protoCompleted {

			pid := pd.ID()

			// this node is not in the set of receivers for this output
			if !sigToReceiverSet[pd.Signature.String()].Contains(s.self) {
				s.Logf("[QueryForOutput] not querying unneeded output for protocol %s", pid)
				continue
			}

			s.Logf("[QueryForOutput] [%s] received aggregated completed", pid)

			if !sigListNoResult.Contains(pd.Signature) {
				s.Logf("[QueryForOutput] not querying known output for protocol %s", pid)
				continue
			}

			// requests output to aggregator.
			aggregatedOutput, err := s.transport.GetAggregationFrom(pkg.NewOutgoingContext(&s.self, &sess.ID, nil), pd.Aggregator, pid)
			if err != nil {
				s.Logf("[QueryForOutput] [%s] got error on output query: %s", pid, err)
				panic(err)
			}

			s.Logf("[QueryForOutput] queried node %s for the protocol %s output", pd.Aggregator, pid)

			var proto protocols.Instance
			proto, err = protocols.NewProtocol(pd, sess) // TODO this resamples the CRP (could be done while waiting for agg)
			if err != nil {
				panic(err)
			}
			out := <-proto.Output(*aggregatedOutput)

			if out.Error != nil {
				s.Logf("[QueryForOutput] Error in protocol %s output: %v", pid, out.Error)
				continue
			}

			outputs <- struct {
				protocols.Descriptor
				protocols.Output
			}{pd, out}
		}
		outQueriesDone <- true
	}()

	return outQueriesDone
}

// storeProtocolOutput stores the protocol's output in the ObjectStore of the node.
func (s *Service) storeProtocolOutput(outputs chan struct {
	protocols.Descriptor
	protocols.Output
}, sess *pkg.Session) {
	for output := range outputs {
		// s.Logf("[Store] Storing output for protocol %s under %s", output.Descriptor.ID, output.Signature.String())

		if output.Result != nil {
			switch res := output.Result.(type) {
			case *rlwe.PublicKey:
				if err := sess.ObjectStore.Store(output.Signature.String(), res); err != nil {
					s.Logf("error on Public Key store: %s", err)
				}
			case *rlwe.RelinearizationKey:
				if err := sess.ObjectStore.Store(output.Signature.String(), res); err != nil {
					s.Logf("error on Relinearization Key store: %s", err)
				}
			case *rlwe.SwitchingKey:
				if err := sess.ObjectStore.Store(output.Signature.String(), res); err != nil {
					s.Logf("error on Rotation Key Store: %s", err)
				}
			default:
				s.Logf("got output for protocol %s: %v", output.ID(), output)
			}
		}
	}
}

func (s *Service) Register(peer transport.Peer) error {
	s.cPeers.L.Lock()
	if _, exists := s.peers[peer.ID()]; exists {
		// return fmt.Errorf("peer with id %s already registered", peer.ID())
		s.Logf("peer %s was already registered", peer.ID())
	}
	s.peers[peer.ID()] = peer
	s.cPeers.L.Unlock()
	s.cPeers.Broadcast()
	s.Logf("peer %v registered for setup", peer.ID())
	return nil
}

func (s *Service) Unregister(peer transport.Peer) error {
	s.cPeers.L.Lock()
	defer s.cPeers.L.Unlock()
	if _, exists := s.peers[peer.ID()]; !exists {
		s.Logf("trying to unregister unregistered peer %s", peer.ID())
		return nil
	}
	delete(s.peers, peer.ID())
	s.cPeers.Broadcast()
	s.Logf("peer %v unregistered", peer.ID())
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

func (s *Service) Logf(msg string, v ...any) {
	log.Printf("%s | %s\n", s.self, fmt.Sprintf(msg, v...))
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
