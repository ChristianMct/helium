package pkg

import (
	"context"
	"fmt"
	"sync"

	"github.com/ldsec/helium/pkg/utils"
)

type PartySet struct {
	peers  utils.Set[NodeID]
	cPeers sync.Cond
	mPeers sync.RWMutex
}

func NewPartySet() *PartySet {
	s := new(PartySet)
	s.peers = utils.NewEmptySet[NodeID]()
	s.cPeers = sync.Cond{L: &s.mPeers}
	return s
}

func (s *PartySet) Register(peer NodeID) error {
	s.cPeers.L.Lock()
	// if _, exists := s.peers[peer]; exists {
	// 	return fmt.Errorf("peer with id %s already registered", peer)
	// 	//s.Logf("peer %s was already registered", peer)
	// }
	s.peers.Add(peer)
	s.cPeers.L.Unlock()
	s.cPeers.Broadcast()
	//s.Logf("peer %v registered for setup", peer.ID())
	return nil
}

func (s *PartySet) Unregister(peer NodeID) error {
	s.cPeers.L.Lock()
	defer s.cPeers.L.Unlock()
	if _, exists := s.peers[peer]; !exists {
		//s.Logf("trying to unregister unregistered peer %s", peer.ID())
		return fmt.Errorf("trying to unregister unregistered peer %s", peer)
	}
	delete(s.peers, peer)
	s.cPeers.Broadcast()
	//s.Logf("peer %v unregistered", peer.ID())
	return nil
}

func (s *PartySet) WaitForRegisteredIDSet(ctx context.Context, size int) (utils.Set[NodeID], error) {
	connset := make(chan utils.Set[NodeID])
	go func() {
		s.cPeers.L.Lock()
		var connected utils.Set[NodeID]
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

func (s *PartySet) registeredIDs() utils.Set[NodeID] {
	connected := make(utils.Set[NodeID])
	for peerID := range s.peers {
		connected.Add(peerID)
	}
	return connected
}
