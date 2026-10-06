package protocols

import (
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"github.com/tuneinsight/lattigo/v6/ring"
	"golang.org/x/crypto/blake2b"
)

// This file implements the masking technique of https://eprint.iacr.org/2026/031,
// Section 5 for the key-switching protocol shares, see Protocol.GenShare.

// maskDomain is the domain separation tag of the mask PRF.
const maskDomain = "helium/key-switch-mask"

// keySwitchInputDigest returns a digest of the ciphertext of a key-switching protocol input.
// It uses blake2b.Sum256 as a digest algorithm.
func keySwitchInputDigest(in Input) ([]byte, error) {
	ksin, ok := in.(*KeySwitchInput)
	if !ok {
		return nil, fmt.Errorf("bad input type: %T instead of %T", in, ksin)
	}
	if ksin.InpuCt == nil {
		return nil, fmt.Errorf("input ciphertext is nil")
	}
	b, err := ksin.InpuCt.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("cannot serialize input ciphertext: %w", err)
	}
	h := blake2b.Sum256(b)
	return h[:], nil
}

// getMaskPRF returns the stream F(key, (S, ct)), where S is the set of participants of pd and
// ct is the input ciphertext with digest ctDigest. The PRF is the keyed BLAKE2b XOF, and its
// input also includes the protocol signature. Each call returns a new stream in its initial state.
func getMaskPRF(key []byte, pd Descriptor, ctDigest []byte) (blake2b.XOF, error) {
	xof, err := blake2b.NewXOF(blake2b.OutputLengthUnknown, key)
	if err != nil {
		return nil, err
	}
	parts := make(sort.StringSlice, len(pd.Participants))
	for i, nid := range pd.Participants {
		parts[i] = string(nid)
	}
	sort.Sort(parts)

	// the fields are length-prefixed so that the encoding of the input is injective
	writeField(xof, []byte(maskDomain))
	writeField(xof, []byte(pd.Signature.String()))
	writeField(xof, binary.BigEndian.AppendUint32(nil, uint32(len(parts))))
	for _, part := range parts {
		writeField(xof, []byte(part))
	}
	writeField(xof, ctDigest)
	return xof, nil
}

func writeField(w io.Writer, b []byte) {
	if _, err := w.Write(binary.BigEndian.AppendUint32(nil, uint32(len(b)))); err != nil {
		panic(err)
	}
	if _, err := w.Write(b); err != nil {
		panic(err)
	}
}

// keySwitchMask returns the node's mask for the protocol. The mask is a polynomial of the provided
// ring.Ring (at the default level for this Ring).
func (p *Protocol) keySwitchMask(ringQ *ring.Ring, ctDigest []byte) (mask ring.Poly, err error) {
	sampler := ring.NewUniformSampler(ringQ)
	mask, buff := ringQ.NewPoly(), ringQ.NewPoly()
	for _, nid := range p.pd.Participants {
		if nid == p.self {
			continue
		}
		mk, err := p.sess.GetMaskKeys(nid)
		if err != nil {
			return mask, err
		}
		own, err := getMaskPRF(mk.Own, p.pd, ctDigest)
		if err != nil {
			return mask, err
		}
		peer, err := getMaskPRF(mk.Peer, p.pd, ctDigest)
		if err != nil {
			return mask, err
		}
		sampler.Read(own, buff)
		ringQ.Add(mask, buff, mask)
		sampler.Read(peer, buff)
		ringQ.Sub(mask, buff, mask)
	}
	return mask, nil
}

// addKeySwitchMask adds the node's mask for the protocol and its input in to pol.
func (p *Protocol) addKeySwitchMask(ctDigest []byte, level int, pol ring.Poly) error {
	if len(ctDigest) == 0 {
		return fmt.Errorf("a ciphertext digest must be provided for computing the mask")
	}
	ringQ := p.sess.Params.GetRLWEParameters().RingQ().AtLevel(level)
	mask, err := p.keySwitchMask(ringQ, ctDigest)
	if err != nil {
		return err
	}
	if mask.Level() != pol.Level() {
		return fmt.Errorf("level mismatch: mask at level %d and target at level %d", mask.Level(), pol.Level())
	}
	ringQ.Add(pol, mask, pol)
	return nil
}

// isMasked returns whether the shares of the protocol must be masked. This is the case for
// the DEC protocol in the T-out-of-N sessions, where the protocol can then be attempted on
// the same ciphertext with different sets of participants.
func (p *Protocol) isMasked() bool {
	return p.pd.Type == DEC && p.sess.IsTOutOfN() // TODO: CKS and PCKS when supported
}
