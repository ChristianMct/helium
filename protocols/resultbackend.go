package protocols

import (
	"errors"
	"fmt"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/objectstore"
)

// ErrResultNotFound is returned by ResultBackend implementations when no
// aggregated share is stored for the requested protocol.
var ErrResultNotFound = errors.New("no stored result for protocol")

// ResultBackend is the (persistent) store of the aggregated shares of completed
// protocols. Aggregated shares are the transferable form of a protocol result;
// the finalized outputs (keys, ciphertexts) are derived from them, see MHEMPC.GetOutput.
//
// Shares are indexed by protocol ID (i.e., by full descriptor), so that retried
// executions of the same signature do not overwrite each other. The backend also
// keeps a signature -> last completed descriptor index, used to restore the
// completion state across restarts.
type ResultBackend interface {
	// Put stores the aggregated share of the protocol described by pd.
	Put(pd Descriptor, aggShare Share) error
	// Get returns the aggregated share of the protocol described by pd.
	// It returns ErrResultNotFound if the backend holds no share for pd.
	Get(pd Descriptor) (Share, error)
	// Has returns whether the backend holds an aggregated share for pd.
	Has(pd Descriptor) (bool, error)
	// CompletedDescriptor returns the last stored descriptor for the given signature, if any.
	CompletedDescriptor(sig Signature) (Descriptor, bool, error)
}

type objStoreResultBackend struct {
	sessID helium.SessionID
	store  objectstore.ObjectStore
}

// NewObjectStoreResultBackend returns a ResultBackend storing the results of the
// given session in the provided object store.
func NewObjectStoreResultBackend(store objectstore.ObjectStore, sessID helium.SessionID) ResultBackend {
	return &objStoreResultBackend{sessID: sessID, store: store}
}

func (b *objStoreResultBackend) shareKey(pd Descriptor) string {
	return fmt.Sprintf("%s/%s-aggshare", b.sessID, pd.ID())
}

func (b *objStoreResultBackend) descKey(sig Signature) string {
	return fmt.Sprintf("%s/%s-desc", b.sessID, sig)
}

func (b *objStoreResultBackend) Put(pd Descriptor, aggShare Share) error {
	if aggShare.MHEShare == nil {
		return fmt.Errorf("cannot store nil share for protocol %s", pd.HID())
	}
	// TODO: as transaction
	if err := b.store.Store(b.shareKey(pd), aggShare.MHEShare); err != nil {
		return err
	}
	return b.store.Store(b.descKey(pd.Signature), &pd)
}

func (b *objStoreResultBackend) Has(pd Descriptor) (bool, error) {
	return b.store.IsPresent(b.shareKey(pd))
}

func (b *objStoreResultBackend) Get(pd Descriptor) (Share, error) {
	has, err := b.store.IsPresent(b.shareKey(pd))
	if err != nil || !has {
		return Share{}, ErrResultNotFound
	}
	share := newAggregatedShare(pd)
	if err := b.store.Load(b.shareKey(pd), share.MHEShare); err != nil {
		return Share{}, fmt.Errorf("could not load share for %s: %w", pd.HID(), err)
	}
	return share, nil
}

func (b *objStoreResultBackend) CompletedDescriptor(sig Signature) (pd Descriptor, has bool, err error) {
	has, err = b.store.IsPresent(b.descKey(sig))
	if err != nil || !has {
		return Descriptor{}, false, err
	}
	err = b.store.Load(b.descKey(sig), &pd)
	return pd, err == nil, err
}

// newAggregatedShare allocates an empty share of the correct lattigo type for pd,
// with the metadata of the completed aggregation.
func newAggregatedShare(pd Descriptor) Share {
	return Share{
		ShareMetadata: ShareMetadata{
			ProtocolID:   pd.ID(),
			ProtocolType: pd.Signature.Type,
			From:         shareProviders(pd),
		},
		MHEShare: pd.Signature.Type.Share(),
	}
}
