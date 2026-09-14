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

// NodeAddress is the network address of a node.
type NodeAddress string

// String returns a string representation of the node address.
func (na NodeAddress) String() string {
	return string(na)
}

// NodeInfo contains the unique identifier and the network address of a node.
type NodeInfo struct {
	NodeID
	NodeAddress
}

// NodeList is a list of known nodes in the network. It must contain all nodes for a
// given application, including the current node. It does not need to contain an
// address for all nodes, except for the helper node.
type NodeList []NodeInfo

// AddressOf returns the network address of the node with the given ID. Returns
// an empty string if the node is not found in the list.
func (nl NodeList) AddressOf(id NodeID) NodeAddress {
	for _, n := range nl {
		if n.NodeID == id {
			return n.NodeAddress
		}
	}
	return ""
}

// Contains returns whether the list contains the node with the given ID.
func (nl NodeList) Contains(id NodeID) bool {
	for _, n := range nl {
		if n.NodeID == id {
			return true
		}
	}
	return false
}

// String returns a string representation of the list of nodes.
func (nl NodeList) String() string {
	str := "[ "
	for _, n := range nl {
		str += fmt.Sprintf(`{ID: %s, Address: %s} `, n.NodeID, n.NodeAddress)
	}
	return str + "]"
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
