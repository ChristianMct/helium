# Changelog

This file contains a log of the main changes made to the framework. 

## [unrelease] 

### Added
- CKKS-based sessions.
- Protocol retries.
- Generic coordination interface.

### Changed
- The `helium` package now provides the main entrypoint to the library, it now implementents the gRPC transport layer and node coordination, on top of the `node` package. 
- The `sessions.Parameters` type now has an interface type field `FHEParameters` for specifiying the FHE scheme parameters. Currently,
`ckks.ParametersLiteral` and `bgv.ParametersLiteral` are supported.
- The `circuits.Runtime` interface now provide a single `EvalLocal` method for specifying local operations.


## [v0.1.0] - 15.03.2024
### Added
- First public `v0` release
