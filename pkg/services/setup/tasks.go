package setup

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/ldsec/helium/pkg/api"

	"google.golang.org/grpc/metadata"
)

type FetchShareTasks struct {
	Protocol ProtocolInt
	ShareRequest
}

func (s *SetupService) Executes(fst *FetchShareTasks) (AggregatedShareInt, error) {
	log.Printf("Node %s | executing task: %s \n", s.ID(), fst)

	isLocal := fst.To == s.ID()
	cli, hasCli := s.peers[fst.To]

	var share AggregatedShareInt
	var err error
	switch {
	case isLocal: // task is local
		share, err = fst.Protocol.GetShare(fst.ShareRequest)
		if err != nil {
			panic(err)
		}
	case hasCli: // task is remote and peer is connected

		ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("session_id", "test-session", "node_id", string(s.ID())))
		// retrieve the previous share from the task if necessary
		var prevShare *api.Share
		if fst.Round > 1 {
			aggShareRoundOne, err := fst.Protocol.GetShare(ShareRequest{ProtocolID: fst.ProtocolID, Round: 1, AggregateFor: fst.Protocol.Descriptor().Participants})
			if err != nil {
				log.Panic(err)
			}

			aggShareRoundOneBytes, err := aggShareRoundOne.Share().MarshalBinary()
			if err != nil {
				return nil, err
			}
			prevShare = &api.Share{ProtocolID: &api.ProtocolID{ProtocolID: string(fst.ProtocolID)}, Round: &fst.Round, Share: aggShareRoundOneBytes}
		}

		//
		aggFor := make([]*api.NodeID, len(fst.AggregateFor))
		for i, nodeId := range fst.AggregateFor {
			aggFor[i] = &api.NodeID{NodeId: string(nodeId)}
		}

		// makes the request to the peer
		sr := &api.ShareRequest{ProtocolID: &api.ProtocolID{ProtocolID: string(fst.ProtocolID)}, Round: &fst.Round, AggregateFor: aggFor, Previous: prevShare}
		peerShare, err := cli.GetShare(ctx, sr)
		if err != nil {
			panic(err)
		}

		share, err = fst.Protocol.GetShare(ShareRequest{AggregateFor: nil}) // Creates an allocated share
		if err != nil {
			return nil, err
		}
		err = share.Share().UnmarshalBinary(peerShare.Share)
		if err != nil {
			return nil, err
		}
	default:
		log.Printf("Node %s | skipped fetch task to unconnected party with id %s \n", s.ID(), fst.To)
		return nil, nil
	}

	share.AggregateFor().Add(fst.To)

	return share, nil
}

func (pft FetchShareTasks) String() string {
	return fmt.Sprintf("ProtocolFetchTask[%s]", pft.ShareRequest)
}

type AggregateTask struct {
	Protocol   ProtocolInt
	fetchTasks []FetchShareTasks
}

var numFetchWorkers = 10

func (s *SetupService) ExecuteAggTask(agt *AggregateTask) error {

	var wg sync.WaitGroup
	tasks := make(chan FetchShareTasks, len(agt.fetchTasks))
	shares := make(chan AggregatedShareInt)

	for i := 1; i <= numFetchWorkers; i++ {
		wg.Add(1)
		go func() {
			for task := range tasks {
				share, err := s.Executes(&task)
				if err != nil {
					panic(err)
				}
				shares <- share
			}
			wg.Done()
		}()
	}

	for _, task := range agt.fetchTasks {
		tasks <- task
	}
	close(tasks)

	go func() {
		wg.Wait()
		close(shares)
	}()

	for share := range shares {
		_, err := agt.Protocol.PutShare(share)
		if err != nil {
			log.Panic(err)
		}
	}

	return nil
}
