package setup

import (
	"context"
	"fmt"

	"github.com/ChristianMct/helium/objectstore"
	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/sessions"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
)

type KeyBackend struct {
	*objStoreResultBackend
	sess *sessions.Session
}

func NewKeyBackend(osc objectstore.Config, sessParams sessions.Parameters) (kb *KeyBackend, err error) {
	kb = new(KeyBackend)
	os, err := objectstore.NewObjectStoreFromConfig(osc)
	if err != nil {
		return nil, err
	}
	kb.objStoreResultBackend = newObjStoreResultBackend(os)
	kb.sess, err = sessions.NewSession("", sessParams, nil)
	if err != nil {
		return nil, err
	}
	return kb, nil
}

// GetCollectivePublicKey returns the collective public key for the session in ctx.
func (kb *KeyBackend) GetCollectivePublicKey(ctx context.Context) (*rlwe.PublicKey, error) {
	out, err := kb.getOutput(ctx, protocols.Signature{Type: protocols.CKG})
	if err != nil {
		return nil, err
	}
	return out.(*rlwe.PublicKey), nil
}

// GetGaloisKey returns the galois key for the session in ctx and the given Galois element.
func (kb *KeyBackend) GetGaloisKey(ctx context.Context, galEl uint64) (*rlwe.GaloisKey, error) {
	out, err := kb.getOutput(ctx, protocols.Signature{Type: protocols.RTG, Args: map[string]string{"GalEl": fmt.Sprintf("%d", galEl)}})
	if err != nil {
		return nil, err
	}
	return out.(*rlwe.GaloisKey), err
}

// GetRelinearizationKey returns the relinearization key for the session in ctx.
func (kb *KeyBackend) GetRelinearizationKey(ctx context.Context) (*rlwe.RelinearizationKey, error) {
	out, err := kb.getOutput(ctx, protocols.Signature{Type: protocols.RKG})
	if err != nil {
		return nil, err
	}
	return out.(*rlwe.RelinearizationKey), err
}

func (kb *KeyBackend) getOutput(ctx context.Context, sig protocols.Signature) (interface{}, error) {
	pd, err := kb.GetProtocolDesc(ctx, sig)
	if err != nil {
		return nil, err
	}
	share := sig.Type.Share()
	err = kb.GetShare(ctx, sig, share)
	if err != nil {
		return nil, err
	}
	aggOut := protocols.AggregationOutput{Descriptor: *pd, Share: protocols.Share{MHEShare: share, ShareMetadata: protocols.ShareMetadata{ProtocolID: pd.ID(), ProtocolType: pd.Type}}}

	p, err := protocols.NewProtocol(*pd, kb.sess)
	if err != nil {
		return nil, err
	}
	in, err := kb.getProtoInput(ctx, p)
	if err != nil {
		return nil, err
	}
	out := protocols.AllocateOutput(sig, *kb.sess.Params.GetRLWEParameters()) // TODO cache ?
	if err = p.Output(in, aggOut, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (kb *KeyBackend) getProtoInput(ctx context.Context, p *protocols.Protocol) (protocols.Input, error) {
	switch p.Descriptor().Type {
	case protocols.CKG, protocols.RTG:
		return p.ReadCRP()
	case protocols.RKG:
		share := p.AllocateShare()
		if err := kb.objStoreResultBackend.GetShare(ctx, protocols.Signature{Type: protocols.RKG1}, share); err != nil {
			return nil, fmt.Errorf("could not retrieve round 1 share: %w", err)
		}
		return share.MHEShare, nil
	default:
		return nil, fmt.Errorf("unsupported protocol type %s", p.Descriptor().Type)
	}
}
