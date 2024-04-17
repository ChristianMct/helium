package session

import "github.com/tuneinsight/lattigo/v5/core/rlwe"

// Ciphertext is a type for ciphertext within the helium framework.
type Ciphertext struct {
	rlwe.Ciphertext
	CiphertextMetadata
}

// CiphertextType is an enumerated type for the types of ciphertexts.
type CiphertextType int

const (
	// Unspecified is the default value for the type of a ciphertext.
	Unspecified CiphertextType = iota
	// BFV is the type of a ciphertext in the BFV scheme.
	BFV
	// BGV is the type of a ciphertext in the BGV scheme.
	BGV
	// CKKS is the type of a ciphertext in the CKKS scheme.
	CKKS
	// RGSW is the type of a ciphertext in the RGSW scheme.
	RGSW
)

var typeToString = [...]string{"Unspecified", "BFV", "BGV", "CKKS", "RGSW"}

// String returns a string representation of the ciphertext type.
func (ctt CiphertextType) String() string {
	if ctt < 0 || int(ctt) > len(typeToString) {
		return "invalid"
	}
	return typeToString[ctt]
}

// CiphertextMetadata contains information on ciphertexts.
// In the current bgv-specific implementation, the type is not used.
type CiphertextMetadata struct {
	ID   CiphertextID
	Type CiphertextType
}
