package setup

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/ldsec/helium/pkg/api"
	"github.com/ldsec/helium/pkg/protocols"

	"google.golang.org/grpc/metadata"
)

type FetchShareTasks struct {
	Protocol protocols.Interface
	protocols.ShareRequest
}

func (s *SetupService) Executes(fst *FetchShareTasks) (protocols.AggregatedShareInt, error) {
	log.Printf("Node %s | executing task: %s \n", s.ID(), fst)

	isLocal := fst.To == s.ID()
	cli, hasCli := s.peers[fst.To]

	var share protocols.AggregatedShareInt
	var err error
	switch {
	case isLocal: // task is local
		share, err = fst.Protocol.GetShare(fst.ShareRequest)
		if err != nil {
			panic(err)
		}
	case hasCli: // task is remote and peer is connected

		ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("session_id", "test-session", "sender_id", string(s.ID()))) // TODO: assumes a single session named "test-session" :D
		// retrieve the previous share from the task if necessary
		var prevShare *api.Share
		if fst.Round > 1 {
			aggShareRoundOne, err := fst.Protocol.GetShare(protocols.ShareRequest{ProtocolID: fst.ProtocolID, Round: 1, AggregateFor: fst.Protocol.Desc().Participants})
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

		share, err = fst.Protocol.GetShare(protocols.ShareRequest{AggregateFor: nil}) // Creates an allocated share
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
	Protocol   protocols.Interface
	fetchTasks []FetchShareTasks
}

var numFetchWorkers = 10

func (s *SetupService) ExecuteAggTask(agt *AggregateTask) error {

	var wg sync.WaitGroup
	tasks := make(chan FetchShareTasks, len(agt.fetchTasks))
	shares := make(chan protocols.AggregatedShareInt)

	for i := 1; i <= numFetchWorkers; i++ {
		wg.Add(1)
		go func() {
			for task := range tasks {
				share, err := s.Executes(&task)
				if err != nil {
					panic(err)
				}
				if share != nil {
					shares <- share
				}
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
