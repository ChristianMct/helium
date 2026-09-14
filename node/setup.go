package node

import (
	"strconv"

	"github.com/ChristianMct/helium"
	"github.com/ChristianMct/helium/protocols"
)

// SignatureList provides utility functions for a list of protocol signatures.
type SignatureList []protocols.Signature

// SetupSignatures returns the list of protocol signatures generating the keys of
// the given setup description.
func SetupSignatures(sd helium.SetupDescription) SignatureList {
	sl := make(SignatureList, 0, 3+len(sd.Gks))
	if sd.Cpk {
		sl = append(sl, protocols.Signature{Type: protocols.CKG})
	}
	if sd.Rlk {
		sl = append(sl, protocols.Signature{Type: protocols.RKG})
	}
	for _, gk := range sd.Gks {
		sl = append(sl, protocols.Signature{Type: protocols.RTG, Args: map[string]string{"GalEl": strconv.FormatUint(gk, 10)}})
	}
	return sl
}

// Contains checks whether the list contains the given signature.
func (sl SignatureList) Contains(other protocols.Signature) bool {
	for _, sig := range sl {
		if sig.Equals(other) {
			return true
		}
	}
	return false
}
