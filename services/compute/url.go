package compute

import (
	"net/url"
	"path"
	"strings"

	"github.com/ChristianMct/helium/sessions"
)

// URL defines a URL format to serve as ciphertext identifier for
// the Helium framwork.
type URL url.URL

// ParseURL parses a string into a helium URL.
func ParseURL(s string) (*URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	return (*URL)(u), nil
}

// NodeID returns the host part of the URL as a NodeID.
func (u *URL) NodeID() sessions.NodeID {
	return sessions.NodeID(u.Host)
}

func (u *URL) CiphertextBaseID() sessions.CiphertextID {
	return sessions.CiphertextID(path.Base(u.Path))
}

func (u *URL) CiphertextID() sessions.CiphertextID {
	return sessions.CiphertextID(u.String())
}

// CircuitID returns the circuit id part of the URL, if any.
// Returns the empty string if no circuit id is present.
func (u *URL) CircuitID() string {
	if dir, _ := path.Split(u.Path); len(dir) > 0 { // ctid belongs to a circuit
		return strings.SplitN(strings.Trim(dir, "/"), "/", 2)[0]
	}
	return ""
}

// String returns the string representation of the URL.
func (u *URL) String() string {
	return (*url.URL)(u).String()
}
