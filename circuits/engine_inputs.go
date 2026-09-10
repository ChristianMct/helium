package circuits

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ChristianMct/helium/sessions"
	"github.com/ChristianMct/helium/utils"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
	"github.com/tuneinsight/lattigo/v5/schemes/ckks"
	"github.com/tuneinsight/lattigo/v5/utils/bignum"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"
)

// sumCRS returns the seed of the common random polynomial used to encrypt the
// contributions to a summed input, so that the evaluator can sum them.
func sumCRS(sess *sessions.Session, cid sessions.CircuitID, name string) []byte {
	var crs []byte
	crs = append(crs, sess.PublicSeed...)
	crs = append(crs, []byte(fmt.Sprintf("%s/%s", cid, name))...)
	return crs
}

// sumContribution returns the summed input name the operand contributes to, if any.
func sumContribution(md *Metadata, id OperandID) (string, bool) {
	for name, ids := range md.SumInputs {
		for _, cid := range ids {
			if cid == id {
				return name, true
			}
		}
	}
	return "", false
}

// sendInputs obtains the node's inputs from the input provider, encrypts them and sends
// them to the evaluator.
func (e *Engine) sendInputs(ctx context.Context, md *Metadata, ids []OperandID) error {
	if len(ids) == 0 {
		return nil
	}

	cpk, err := e.keys.GetCollectivePublicKey(ctx)
	if err != nil {
		return fmt.Errorf("cannot retrieve the collective public key: %w", err)
	}
	enc, err := newInputEncryptor(e.sess, cpk)
	if err != nil {
		return err
	}

	e.mu.Lock()
	ip := e.inputs
	e.mu.Unlock()

	inChan, err := ip(ctx, md.Descriptor.Clone(), sortedIDs(ids))
	if err != nil {
		return fmt.Errorf("input provider error: %w", err)
	}

	expected := utils.NewSet(ids)
	provided := utils.NewEmptySet[OperandID]()
	for in := range inChan {
		if !expected.Contains(in.ID) {
			e.Logf("skipping unexpected input %s", in.ID)
			continue
		}
		if provided.Contains(in.ID) {
			e.Logf("skipping duplicated input %s", in.ID)
			continue
		}
		ct, err := enc.encrypt(md, in)
		if err != nil {
			return fmt.Errorf("cannot encrypt input %s: %w", in.ID, err)
		}
		if err := e.trans.PutOperand(ctx, md.Descriptor, Operand{ID: in.ID, Ciphertext: ct}); err != nil {
			return fmt.Errorf("cannot send input %s: %w", in.ID, err)
		}
		provided.Add(in.ID)
		e.Logf("sent input %s", in.ID)
	}

	if missing := expected.Diff(provided); len(missing) > 0 {
		return fmt.Errorf("input provider did not provide %v", sortedIDs(missing.Elements()))
	}
	return nil
}

// inputEncryptor encodes and encrypts a node's inputs under the collective public key,
// or under the node's group secret key with a common random polynomial for summed inputs.
type inputEncryptor struct {
	sess      *sessions.Session
	encoder   any
	encryptor *rlwe.Encryptor
}

func newInputEncryptor(sess *sessions.Session, cpk *rlwe.PublicKey) (*inputEncryptor, error) {
	ie := &inputEncryptor{sess: sess, encryptor: rlwe.NewEncryptor(sess.Params, cpk)}
	switch p := sess.Params.(type) {
	case bgv.Parameters:
		ie.encoder = bgv.NewEncoder(p)
	case ckks.Parameters:
		ie.encoder = ckks.NewEncoder(p)
	default:
		return nil, fmt.Errorf("session has unsupported parameters type: %T", p)
	}
	return ie, nil
}

func (ie *inputEncryptor) encrypt(md *Metadata, in Input) (*rlwe.Ciphertext, error) {
	sumName, isSum := sumContribution(md, in.ID)

	var pt *rlwe.Plaintext
	switch v := in.Value.(type) {
	case *rlwe.Ciphertext:
		if isSum {
			return nil, fmt.Errorf("contributions to summed inputs must be provided in plaintext")
		}
		if v == nil {
			return nil, fmt.Errorf("nil ciphertext")
		}
		return v, nil
	case *rlwe.Plaintext:
		if v == nil {
			return nil, fmt.Errorf("nil plaintext")
		}
		pt = v
	default:
		var err error
		if pt, err = ie.encode(in.Value); err != nil {
			return nil, err
		}
	}

	if !isSum {
		return ie.encryptor.EncryptNew(pt)
	}

	// summed input: encrypts under the group secret key, with the CRS as the uniform polynomial
	sk, err := ie.sess.GetSecretKeyForGroup(md.SumNodes(sumName))
	if err != nil {
		return nil, fmt.Errorf("cannot get group secret key for summed input %s: %w", sumName, err)
	}
	prng, err := sampling.NewKeyedPRNG(sumCRS(ie.sess, md.CircuitID, sumName))
	if err != nil {
		return nil, err
	}
	return rlwe.NewEncryptor(ie.sess.Params, sk).WithPRNG(prng).EncryptNew(pt)
}

func (ie *inputEncryptor) encode(v any) (*rlwe.Plaintext, error) {
	switch enc := ie.encoder.(type) {
	case *bgv.Encoder:
		switch v.(type) {
		case []uint64, []int64:
		default:
			return nil, fmt.Errorf("invalid input type %T for BGV", v)
		}
		params := ie.sess.Params.(bgv.Parameters)
		pt := bgv.NewPlaintext(params, params.MaxLevel())
		return pt, enc.Encode(v, pt)
	case *ckks.Encoder:
		switch v.(type) {
		case []complex128, []*bignum.Complex, []float64, []*big.Float:
		default:
			return nil, fmt.Errorf("invalid input type %T for CKKS", v)
		}
		params := ie.sess.Params.(ckks.Parameters)
		pt := ckks.NewPlaintext(params, params.MaxLevel())
		return pt, enc.Encode(v, pt)
	default:
		return nil, fmt.Errorf("unsupported encoder type %T", enc)
	}
}
