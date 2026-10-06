// Package circuits implements the evaluation of the circuits defined in the helium
// package. It mirrors the protocols package: a circuit evaluation is a single-round
// protocol with the parties' encrypted data as input and the encrypted circuit's output
// as output.
//
// The Runner type is the node-side state machine of this protocol, the sibling of
// protocols.Runner. It is driven by the events of a Coordinator (Started, published
// by the node requesting the evaluation, then Executing, Completed and Failed,
// published by the evaluator) and exchanges the circuits' operands through an
// OperandTransport. A node provides its inputs through the runner's InputProvider,
// and the outputs of a completed circuit are fetched lazily from the evaluator.
//
// The runner evaluates a circuit by running its function against a runtime
// (helium.CircuitRuntime) that resolves the circuit's ports to the operands received
// from the transport, and that provides an evaluator holding the keys declared by the
// circuit's interface.
package circuits
