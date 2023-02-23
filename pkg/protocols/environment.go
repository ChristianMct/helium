package protocols

type ShareQuery struct {
	ShareDescriptor
	Result chan Share
}

type Transport interface {
	OutgoingShares() chan<- Share
	IncomingShares() <-chan Share
}

type Status int32

const (
	OK Status = iota
	Running
	Failed
)

type StatusUpdate struct {
	Descriptor
	Status
}
