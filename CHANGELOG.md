# Changelog

This file contains a log of the main changes made to the framework. 

## [Unreleased]

This update collapses the MHE-MPC protocol logic, previously spread over the `node`,
`services/setup`, `services/compute` and `protocols` packages, into two types of the
`protocols` package, in preparation for the peer-to-peer setting.

### Added

- The `protocols.MHEMPC` type: a state machine executing the MHE protocols (in the aggregator,
  participant and receiver roles) as driven by the events of a `protocols.Coordinator`, and holding
  the protocols' results (fetched lazily from the aggregator when not available locally).
- The `protocols.CentralCoordinator` type: the coordination decisions (participant selection,
  retries, multi-round protocols) and the event log of the helper-assisted setting.
- The `protocols.Executing` event, published by a protocol's aggregator when it is ready to receive
  shares; participants send their share only after this event.
- The `protocols.KeyProvider` view, returning the setup keys from an `MHEMPC` engine.
- The `coordinator.Log` generic event log.

### Changed

- The `helium.HeliumServer` and `helium.HeliumClient` types now instantiate the session, the protocol
  engine, the coordinator (helper only), the compute service and the gRPC transport directly.
- The `compute.Service` runs its key-switching protocols through an `MHEMPC` engine.
- The `node.Config`, `node.App`, `node.List` and `node.SecretProvider` types moved to the `helium`
  package; `node.Config` now has `ProtocolsConfig`, `CoordinatorConfig` and `ComputeConfig` fields.
- The `NodeEvent` protobuf message is now a `oneof` of `ProtocolEvent` and `CircuitEvent`.

### Removed

- The `node` package, the `setup.Service` (and its key backend), the `protocols.Executor` and
  `protocols.CompleteMap` types, and the `coordinator.TestCoordinator` type.

## [v0.3.0] - 20.06.2025 

This update packages various features introduced in the last year, mostly to support
project using Helium.

### Added

- Circuit runtime can now access circuit Descriptor information such as the signature's
  arguments. This enables "runtime" arguments to be passed to circuits.
- A `circuits.TestRuntime` type that implements the `circuits.Runtime` interface for local
  test purposes. It provides a simplified setup/input/evaluation/output to test circuits
  locally without instantiating a full set of service.
- The `circuits.Input` type to represent circuit inputs.
- The `circuits.Runtime.CircuitDescriptor` method for accessing a running circuits'
  metadata (esp. its signature's arguments). 
- The `circuits.Runtime.InputSum` method for efficient handling of directly-summed inputs
  from the session's threshold-number of parties.
- Client nodes can now submit circuit-evaluation requests.
- The `node.SecretProvider` interface for provisioning of the node's secret-keys.

### Changed 

- The `compute.InputProvider` interface is now called only once per circuit. It now takes
  as input a `circuits.Descriptor` instead of a single `circuits.OperandLabel`, and must
  return a channel of `circuits.Input` that will be consumed by the framework.
  

## [v0.2.1] - 23.04.2024 

This update is mainly aimed at triggering the archiving by Zenodo.

### Changed

- Reduced some log output

## [v0.2.0] - 22.04.2024 

### Added

- CKKS-based sessions.
- Protocol retries.
- Generic coordination interface.

### Changed

- The `helium` package now provides the main entrypoint to the library, it now
  implementents the gRPC transport layer and node coordination, on top of the `node`
  package. 
- The `sessions.Parameters` type now has an interface type field `FHEParameters` for
specifiying the FHE scheme parameters. Currently, `ckks.ParametersLiteral` and
`bgv.ParametersLiteral` are supported.
- The `circuits.Runtime` interface now provide a single `EvalLocal` method for specifying
  local operations.

### Fixed 

- Many deadlocks and concurrency issues.

## [v0.1.0] - 15.03.2024

### Added

- First public `v0` release
