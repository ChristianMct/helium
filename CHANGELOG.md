# Changelog

This file contains a log of the main changes made to the framework. 
## [unreleased] 

### Added

- Circuit runtime can now access circuit Descriptor information such as the signature's
  arguments. This enables "runtime" arguments to be passed to circuits.
- A `circuits.TestRuntime` type that implements the `circuits.Runtime` interface for local
  test purposes. It provides a simplified setup/input/evaluation/output to test circuits
  locally without instantiating a full set of service.
- The `circuits.Input` type to represent circuit inputs.

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
