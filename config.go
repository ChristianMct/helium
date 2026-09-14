package helium

import "fmt"

// Config is the configuration of a Helium node, independently of the setting it
// runs in. The setting-specific packages embed it in their own configuration
// (see helper.Config).
type Config struct {
	// ID is the node's own identifier.
	ID NodeID
	// SessionParameters describes the session the node takes part in.
	SessionParameters Parameters
	// MaxParticipation is the maximum number of protocols the node participates in
	// concurrently. Zero means no limit.
	MaxParticipation int
	// MaxEvaluation is the maximum number of circuits the node evaluates concurrently.
	// Zero selects the engine's default.
	MaxEvaluation int
	// ObjectStore configures the node's persistent store for the protocol results.
	ObjectStore ObjectStoreConfig
}

// SetupDescription describes the MHE setup phase of an application: the keys that
// must be generated before the circuits can be evaluated.
//   - Cpk: the collective public key, under which the inputs are encrypted,
//   - Rlk: the relinearization key, for homomorphic multiplications,
//   - Gks: the Galois keys, identified by their Galois elements, for rotations.
type SetupDescription struct {
	Cpk bool
	Rlk bool
	Gks []uint64
}

// String returns a string representation of the setup description.
func (sd SetupDescription) String() string {
	return fmt.Sprintf(`
	{
		Cpk: %v,
		GaloisKeys: %v,
		Rlk: %v,
	}`, sd.Cpk, sd.Gks, sd.Rlk)
}
