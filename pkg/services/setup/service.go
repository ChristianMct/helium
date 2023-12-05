package setup

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/objectstore"
	"github.com/ldsec/helium/pkg/pkg"
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

	peers      *pkg.PartySet
	aggregator pkg.NodeID

	runningProtosMu sync.RWMutex
	runningProtos   map[pkg.ProtocolID]struct {
		pd       protocols.Descriptor
		incoming chan protocols.Share
	}

	completedProtoMu sync.RWMutex
	completedProtos  []protocols.Descriptor

	//outLock    sync.RWMutex
	//aggOutputs map[pkg.ProtocolID]*protocols.AggregationOutput

	ResultBackend

	*drlwe.Combiner
}

func NewSetupService(ownId, aggregatorId pkg.NodeID, sessions pkg.SessionProvider, trans transport.SetupServiceTransport, objStore objectstore.ObjectStore) (s *Service, err error) {
	s = new(Service)

	s.self = ownId
	s.sessions = sessions

	s.peers = pkg.NewPartySet()
	s.aggregator = aggregatorId

	s.runningProtos = make(map[pkg.ProtocolID]struct {
		pd       protocols.Descriptor
		incoming chan protocols.Share
	})

	s.completedProtos = make([]protocols.Descriptor, 0)

	//s.aggOutputs = make(map[pkg.ProtocolID]*protocols.AggregationOutput)

	s.transport = trans

	s.ResultBackend = newObjStoreResultBackend(objStore)

	return s, nil
}

// Execute executes the ProtocolFetchShareTasks of s. These tasks consist in retrieving the share from each peer in the
// protocol and aggregating the shares.
func (s *Service) Execute(ctx context.Context, sd Description) error {

	s.Logf("started Execute")

	sess, exists := s.sessions.GetSessionFromContext(ctx)
	if !exists {
		panic("test session does not exist")
	}

	// 1. INITIALIZATION: generate the list of protocols signatures to execute and relative receivers
	sigList, sigToReceiverSet := DescriptionToSignatureList(sd)

	// keep track of protocols whose results are already available
	sigListNoResult, sigListHasResult := s.filterSignatureList(sigList)
	s.Logf("protocol results can be loaded from the object store: %s", sigListHasResult)
	s.Logf("protocol will be executed: %s", sigListNoResult)

	// 2. REGISTRATION: register for setup to the aggregator
	outCtx := pkg.GetOutgoingContext(context.Background(), s.self)
	protosUpdatesChan := s.registerToAggregatorsForSetup(utils.NewSingletonSet(s.aggregator), outCtx)

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
	if s.aggregator == s.self {
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

	s.transport.Close()

	s.Logf("execute returned")
	return nil
}

// func (s *Service) Shutdown() {
// 	s.transport.Close()
// }

// filterSignatureList splits a SignatureList into two lists based on the presence of the protocol's output in the ObjectStore.
func (s *Service) filterSignatureList(sl SignatureList) (noResult, hasResult SignatureList) {
	noResult, hasResult = make(SignatureList, 0), make(SignatureList, 0)
	for _, sig := range sl {
		has, err := s.ResultBackend.Has(sig)
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

// registerToAggregatorsForSetup registers the caller to all aggregators in the aggregator set of node ids.
// Returns a channel where protocols updates are sent.
func (s *Service) registerToAggregatorsForSetup(aggregators utils.Set[pkg.NodeID], outCtx context.Context) <-chan protocols.StatusUpdate {
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
			// register aggregator to the transport for the setup protocol.
			protoUpdateChannel, present, err := s.transport.RegisterForSetupAt(outCtx, agg)
			if err != nil {
				s.Logf("could not register to aggregator %s: %s", agg, err)
				aggDone.Done()
				return
			}
			s.Logf("[Register] registered to aggregator %s", agg)

			err = s.catchUp(protoUpdateChannel, present, protosUpdatesChan)
			if err != nil {
				panic(fmt.Errorf("error while catching up: %w", err))
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
					aggregatedOutput, err := s.transport.GetAggregationFrom(pkg.NewOutgoingContext(&s.self, &sess.ID, nil), pd.Aggregator, protocols.Descriptor{Signature: protocols.Signature{Type: protocols.RKG_1}, Participants: pd.Participants})
					if err != nil {
						s.Logf("[participate] [%s] got error on output query: %s", pid, err)
						panic(err)
					}
					proto.Init(aggregatedOutput.Share.MHEShare)
				} else {
					crp, err := proto.ReadCRP()
					if err != nil {
						panic(err)
					}
					proto.Init(crp)
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
					online, err := s.peers.WaitForRegisteredIDSet(context.Background(), sess.T-len(partSet))
					if err != nil {
						panic(err)
					}

					// randomizes the remaining participants among the set of registered peers
					online.Remove(partSet.Elements()...)
					partSet.AddAll(utils.GetRandomSetOfSize(sess.T-len(partSet), online))

					// select T parties at random
					pd.Participants = partSet.Elements()
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
				s.transport.PutProtocolUpdate(protocols.StatusUpdate{Descriptor: pd, Status: protocols.Running})

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
					proto.Init(currRlkShare.MHEShare)
				} else {
					crp, err := proto.ReadCRP()
					if err != nil {
						panic(err)
					}
					proto.Init(crp)
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

				err = s.ResultBackend.Put(pd, aggOut.Share)
				if err != nil {
					panic(err)
				}

				s.runningProtosMu.Lock()
				delete(s.runningProtos, pid)
				s.runningProtosMu.Unlock()

				s.completedProtoMu.Lock()
				s.completedProtos = append(s.completedProtos, pd)
				s.completedProtoMu.Unlock()

				s.transport.PutProtocolUpdate(protocols.StatusUpdate{Descriptor: pd, Status: protocols.Status(api.ProtocolStatus_OK)})

				if pd.Signature.Type == protocols.RKG_1 {
					currRlkShare = aggOut.Share
					s.Logf("starting RKG round 2")
					pdAggs <- protocols.Descriptor{Signature: protocols.Signature{Type: protocols.RKG_2}, Participants: pd.Participants, Aggregator: s.self}
				}

				wgSig.Done()
			}
			wg.Done()
		}()
	}

	allAggsDone := make(chan bool, 1)
	go func() {
		wg.Wait()
		allAggsDone <- true
	}()

	return allAggsDone
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
				//s.Logf("[QueryForOutput] not querying unneeded output for protocol %s", pid)
				continue
			}

			if !sigListNoResult.Contains(pd.Signature) {
				//s.Logf("[QueryForOutput] not querying known output for protocol %s", pid)
				continue
			}

			//s.Logf("[QueryForOutput] [%s] received aggregated completed", pid)

			// requests output to aggregator.
			aggregatedOutput, err := s.transport.GetAggregationFrom(pkg.NewOutgoingContext(&s.self, &sess.ID, nil), pd.Aggregator, pd)
			if err != nil {
				//s.Logf("[QueryForOutput] [%s] got error on output query: %s", pid, err)
				panic(err)
			}

			s.Logf("[QueryForOutput] queried node %s for the protocol %s output", pd.Aggregator, pid)

			s.ResultBackend.Put(pd, aggregatedOutput.Share)

			// var proto protocols.Instance
			// proto, err = protocols.NewProtocol(pd, sess) // TODO this resamples the CRP (could be done while waiting for agg)
			// if err != nil {
			// 	panic(err)
			// }
			// out := <-proto.Output(*aggregatedOutput)

			// if out.Error != nil {
			// 	s.Logf("[QueryForOutput] Error in protocol %s output: %v", pid, out.Error)
			// 	continue
			// }

			// outputs <- struct {
			// 	protocols.Descriptor
			// 	protocols.Output
			// }{pd, out}
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
			case *rlwe.GaloisKey:
				if err := sess.ObjectStore.Store(output.Signature.String(), res); err != nil {
					s.Logf("error on Rotation Key Store: %s", err)
				}
			case *drlwe.RelinearizationKeyGenShare:
				if err := sess.ObjectStore.Store(output.Signature.Type.String(), res); err != nil {
					s.Logf("error on Relinearization Key Share store: %s", err)
				}
			default:
				s.Logf("got output for protocol %s: %v", output.ID(), output)
			}
		}
	}
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

func (s *Service) GetProtocolOutput(pd protocols.Descriptor) (*protocols.AggregationOutput, error) {
	share := pd.Signature.Type.Share()
	err := s.ResultBackend.GetShare(pd.Signature, share)
	if err != nil {
		return nil, err
	}
	return &protocols.AggregationOutput{Share: protocols.Share{ShareDescriptor: protocols.ShareDescriptor{Type: pd.Signature.Type}, MHEShare: share}}, nil
}

// Register is called by the transport when a new peer register itself for the setup.
func (s *Service) Register(peer pkg.NodeID) error {
	if err := s.peers.Register(peer); err != nil {
		s.Logf("error when registering peer %s for compute: %s", peer, err)
		return err
	}
	s.Logf("setup service registered peer %v", peer)
	return nil // TODO: Implement
}

// Unregister is called by the transport when a peer is unregistered from the setup.
func (s *Service) Unregister(peer pkg.NodeID) error {
	if err := s.peers.Unregister(peer); err != nil {
		s.Logf("error when unregistering peer %s for compute: %s", peer, err)
		return err
	}
	s.Logf("setup unregistered peer %v", peer)
	return nil // TODO: Implement
}

func (s *Service) Logf(msg string, v ...any) {
	log.Printf("%s | %s\n", s.self, fmt.Sprintf(msg, v...))
}

func (s *Service) catchUp(puChan <-chan protocols.StatusUpdate, present int, pus chan protocols.StatusUpdate) error {
	if present == 0 {
		return nil
	}

	var current int
	runningProtos := make(map[pkg.ProtocolID]protocols.StatusUpdate)
	completedProtos := make([]protocols.StatusUpdate, 0)
	for pu := range puChan {

		switch pu.Status {
		case protocols.Running:
			runningProtos[pu.ID()] = pu
		case protocols.OK, protocols.Failed:
			if _, has := runningProtos[pu.ID()]; !has {
				return fmt.Errorf("protocol OK before creation")
			}
			delete(runningProtos, pu.ID())
			if pu.Status == protocols.OK {
				completedProtos = append(completedProtos, pu)
			}
		}

		current++
		if current == present {
			break
		}
	}

	// puts the currently running protocols first in the queue
	for pid, pu := range runningProtos {
		s.Logf("is catching up on protocol %s", pid)
		pus <- pu
	}

	// puts the completed protocols
	for _, pu := range completedProtos {
		pus <- pu
	}

	return nil
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
