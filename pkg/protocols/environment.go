package protocols

type ShareQuery struct {
	ShareDescriptor
	Result chan Share
}

type Environment interface {
	ShareQuery(ShareQuery)
	OutgoingShares() chan<- Share
	IncomingShares() <-chan Share
	IncomingShareQueries() <-chan ShareQuery
}
