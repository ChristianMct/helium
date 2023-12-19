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

const numProtoPerNode int = 3

type Service struct {
	self pkg.NodeID

	sessions  pkg.SessionProvider
	transport transport.SetupServiceTransport

	//peers      *pkg.PartySet
	aggregator pkg.NodeID

	L sync.RWMutex
	C sync.Cond

	//runningProtosMu sync.RWMutex
	runningProtos map[pkg.ProtocolID]struct {
		pd           protocols.Descriptor
		incoming     chan protocols.Share
		disconnected chan pkg.NodeID
	}

	//connectedNodesMu   sync.RWMutex
	//connectedNodesCond sync.Cond
	connectedNodes map[pkg.NodeID]utils.Set[pkg.ProtocolID]

	//completedProtoMu sync.RWMutex
	completedProtos []protocols.Descriptor

	//outLock    sync.RWMutex
	//aggOutputs map[pkg.ProtocolID]*protocols.AggregationOutput

	ResultBackend
	rkgRound1Results map[pkg.ProtocolID]protocols.Share

	*drlwe.Combiner
}

func NewSetupService(ownId, aggregatorId pkg.NodeID, sessions pkg.SessionProvider, trans transport.SetupServiceTransport, objStore objectstore.ObjectStore) (s *Service, err error) {
	s = new(Service)

	s.self = ownId
	s.sessions = sessions

	//s.peers = pkg.NewPartySet()
	s.aggregator = aggregatorId

	s.runningProtos = make(map[pkg.ProtocolID]struct {
		pd           protocols.Descriptor
		incoming     chan protocols.Share
		disconnected chan pkg.NodeID
	})

	s.completedProtos = make([]protocols.Descriptor, 0)

	//s.aggOutputs = make(map[pkg.ProtocolID]*protocols.AggregationOutput)

	s.transport = trans

	s.ResultBackend = newObjStoreResultBackend(objStore)
	s.rkgRound1Results = make(map[pkg.ProtocolID]protocols.Share)

	s.connectedNodes = make(map[pkg.NodeID]utils.Set[pkg.ProtocolID])

	s.C = sync.Cond{L: &s.L}

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
	s.Logf("%d protocols in the setup: %d in object store + %d to be executed", len(sigList), len(sigListHasResult), len(sigListNoResult))

	// 2. REGISTRATION: register for setup to the aggregator
	outCtx := pkg.GetOutgoingContext(context.Background(), s.self)
	protosUpdatesChan := s.registerToAggregatorsForSetup(utils.NewSingletonSet(s.aggregator), outCtx)

	// split protocols updates into to run and completed.
	protoToRun, protoCompleted := make(chan protocols.Descriptor), make(chan protocols.Descriptor)
	go func() {
		// every time it receives a protocol update, puts the protocol descriptor
		// in the protocols to run or in the protocols completed
		for protoUpdate := range protosUpdatesChan {
			//s.Logf("got protocol update for protocol %s : status: %v ", protoUpdate.HID(), protoUpdate.Status)
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
			s.L.RLock()
			proto, protoExists := s.runningProtos[incShare.ProtocolID]
			s.L.RUnlock()
			if !protoExists {
				s.Logf("dropped share from sender %s: protocol %s is not running", incShare.From, incShare.ProtocolID)
				continue
			}
			// sends received share to the incoming channel of the destination protocol.
			proto.incoming <- incShare
			s.Logf("received share from sender %s for protocol %s", incShare.From, incShare.ProtocolID)
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

func (s *Service) getAvailable() utils.Set[pkg.NodeID] {
	available := make(utils.Set[pkg.NodeID])
	for nid, nProtos := range s.connectedNodes {
		if len(nProtos) < numProtoPerNode {
			available.Add(nid)
		}
	}
	return available
}

func (s *Service) getProtocolDescriptor(sig protocols.Signature, threshold int) protocols.Descriptor {
	pd := protocols.Descriptor{Signature: sig, Aggregator: s.self}

	var available utils.Set[pkg.NodeID]
	for available = s.getAvailable(); len(available) < threshold; available = s.getAvailable() {
		s.C.Wait()
	}

	selected := utils.GetRandomSetOfSize(threshold, available)
	pd.Participants = selected.Elements()
	for nid := range selected {
		s.connectedNodes[nid].Add(pd.ID())
	}

	return pd
}

func (s *Service) runProtocolDescriptor(ctx context.Context, pd protocols.Descriptor, sess *pkg.Session) (*protocols.AggregationOutput, error) {

	proto, err := protocols.NewProtocol(pd, sess)
	if err != nil {
		panic(err)
	}

	pid := pd.ID()
	incoming := make(chan protocols.Share)
	disconnected := make(chan pkg.NodeID)
	s.runningProtos[pd.ID()] = struct {
		pd           protocols.Descriptor
		incoming     chan protocols.Share
		disconnected chan pkg.NodeID
	}{
		pd:           pd,
		incoming:     incoming,
		disconnected: disconnected,
	}
	s.L.Unlock()

	s.Logf("starting %s", pd.HID())
	// sending pd to list of chosen parties.
	s.transport.PutProtocolUpdate(protocols.StatusUpdate{Descriptor: pd, Status: protocols.Running})

	// blocking, returns the result of the aggregation.
	//s.Logf("[Aggregate] Waiting to finish aggregation for pd: %v", pd)

	var crp protocols.CRP
	if pd.Signature.Type == protocols.RKG_2 {
		rkgRound1Pd := protocols.Descriptor{Signature: protocols.Signature{Type: protocols.RKG_1, Args: pd.Signature.Args}, Participants: pd.Participants, Aggregator: pd.Aggregator}
		var has bool
		if crp, has = s.rkgRound1Results[rkgRound1Pd.ID()]; !has {
			panic(fmt.Errorf("started RKG round 2 without result from round 1"))
		}
	} else {
		crp, err = proto.ReadCRP()
		if err != nil {
			panic(err)
		}

	}
	proto.Init(crp)

	var aggOut protocols.AggregationOutput
	var errAgg error
	for done := false; !done; {
		select {
		case aggOut = <-proto.Aggregate(ctx, &ProtocolTransport{incoming: incoming, outgoing: s.transport.OutgoingShares()}):
			if aggOut.Error != nil {
				panic(aggOut.Error)
			}
			done = true
		case participantId := <-disconnected:

			if proto.HasShareFrom(participantId) {
				s.Logf("node %s disconnected after providing its share", participantId)
				continue
			}

			done = true
			errAgg = fmt.Errorf("participant disconnected before providing its share: %s", participantId)
		}
	}

	//s.Logf("[Aggregate] Finished aggregating for pd: %v", pd)

	s.L.Lock()
	delete(s.runningProtos, pid)

	s.completedProtos = append(s.completedProtos, pd)

	for _, participantId := range pd.Participants {
		s.connectedNodes[participantId].Remove(pid)
	}
	s.L.Unlock()
	s.C.Broadcast()

	return &aggOut, errAgg
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
	sigs := make(chan protocols.Signature, len(sigList))
	wgSig := sync.WaitGroup{}
	wgSig.Add(len(sigList))
	for _, sig := range sigList {
		if sig.Type != protocols.RKG_2 { // RKG_2 sig is run directly after round 1
			sigs <- sig
		}
	}

	go func() {
		wgSig.Wait()
		close(sigs)
	}()

	var wg sync.WaitGroup
	for w := 0; w < parallelAggregation; w++ {
		wg.Add(1)
		go func() {
			// for every protocol for which the current node is aggregator
			for sig := range sigs { // TODO NEXT: this could be a priority queue of struct{Descriptor, Context} and retries are simply a new Descriptor with higher priority (the first protocol to succeed cancels the context)

				s.L.Lock()
				pd := s.getProtocolDescriptor(sig, sess.T)

				aggOut, err := s.runProtocolDescriptor(ctx, pd, sess)
				if err != nil {
					s.Logf("error while running protocol %s: %s, requeuing", pd.HID(), err)
					sigs <- sig
					continue
				}

				if sig.Type == protocols.RKG_1 {
					s.rkgRound1Results[pd.ID()] = aggOut.Share
					pdRkgRound2 := protocols.Descriptor{Signature: protocols.Signature{Type: protocols.RKG_2, Args: pd.Signature.Args}, Participants: pd.Participants, Aggregator: pd.Aggregator}
					s.L.Lock()
					aggOutRound2, err := s.runProtocolDescriptor(ctx, pdRkgRound2, sess)
					if err != nil {
						s.Logf("error while running RKG_2 protocol: %s, requeuing RKG_1", err)
						sigs <- sig
						continue
					}
					err = s.ResultBackend.Put(pdRkgRound2, aggOutRound2.Share)
					if err != nil {
						panic(err)
					}

					s.transport.PutProtocolUpdate(protocols.StatusUpdate{Descriptor: pdRkgRound2, Status: protocols.Status(api.ProtocolStatus_OK)})
					wgSig.Done()
				}

				err = s.ResultBackend.Put(pd, aggOut.Share)
				if err != nil {
					panic(err)
				}

				s.transport.PutProtocolUpdate(protocols.StatusUpdate{Descriptor: pd, Status: protocols.Status(api.ProtocolStatus_OK)})
				wgSig.Done()

				s.Logf("[Aggregate] completed sig: %s", pd.Signature)

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

				s.L.Lock()
				_, running := s.runningProtos[pid]
				// already running, next pd.
				if running {
					s.L.Unlock()
					continue
				}

				// add protocols to running protocols
				inc := make(chan protocols.Share)
				s.runningProtos[pid] = struct {
					pd           protocols.Descriptor
					incoming     chan protocols.Share
					disconnected chan pkg.NodeID
				}{
					pd:           pd,
					incoming:     inc,
					disconnected: nil,
				}
				s.L.Unlock()

				// DEBUG
				//s.Logf("[Participate] Making new protocol pd: %v", pd)
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
	s.L.RLock()
	comp := make([]protocols.StatusUpdate, 0, len(s.completedProtos)+len(s.runningProtos))
	for _, p := range s.runningProtos {
		comp = append(comp, protocols.StatusUpdate{Descriptor: p.pd, Status: protocols.Running})
	}
	for _, pd := range s.completedProtos {
		comp = append(comp, protocols.StatusUpdate{Descriptor: pd, Status: protocols.OK})
	}
	s.L.RUnlock()
	return comp
}

func (s *Service) GetProtocolOutput(pd protocols.Descriptor) (*protocols.AggregationOutput, error) {
	var share protocols.LattigoShare
	if pd.Signature.Type == protocols.RKG_1 {
		share = s.rkgRound1Results[pd.ID()]
	} else {
		share = pd.Signature.Type.Share()
		err := s.ResultBackend.GetShare(pd.Signature, share)
		if err != nil {
			return nil, err
		}
	}

	return &protocols.AggregationOutput{Share: protocols.Share{ShareDescriptor: protocols.ShareDescriptor{Type: pd.Signature.Type}, MHEShare: share}}, nil
}

// Register is called by the transport when a new peer register itself for the setup.
func (s *Service) Register(peer pkg.NodeID) error {
	s.L.Lock()
	defer s.C.Broadcast()
	defer s.L.Unlock()

	if _, has := s.connectedNodes[peer]; has {
		panic("attempting to register a registered node")
	}

	s.connectedNodes[peer] = make(utils.Set[pkg.ProtocolID])

	s.Logf("setup service registered peer %v", peer)
	return nil // TODO: Implement
}

// Unregister is called by the transport when a peer is unregistered from the setup.
func (s *Service) Unregister(peer pkg.NodeID) error {

	s.L.Lock()
	protoIDs, has := s.connectedNodes[peer]
	if !has {
		panic("unregistering an unregistered node")
	}

	for pid := range protoIDs {
		s.runningProtos[pid].disconnected <- peer
	}

	delete(s.connectedNodes, peer)
	s.L.Unlock()

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
