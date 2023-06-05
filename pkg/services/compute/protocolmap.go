package compute

import pkg "github.com/ldsec/helium/pkg/session"

type Description struct {
	CircuitName string
	Receiver    Receiver // reduntant but necessary for json marshalling, another possibility is a json annotation
}

type Receiver struct {
	ID       pkg.NodeID
	External bool
	PkFile   string
}
