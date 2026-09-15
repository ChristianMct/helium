# Changelog

This file contains a log of the main changes made to the framework. 

## [Unreleased]

This update collapses the MHE-MPC protocol logic, previously spread over the `node`,
`services/setup`, `services/compute` and `protocols` packages, into two runner types, and
inverts the package graph so that an application deals with the `helium` package and the
package of its setting only, in preparation for the peer-to-peer setting.

### Added

- The `helium.App.Main` function and the `helium.Runtime` interface: every node runs `Main`, which
  evaluates circuits (`Runtime.Evaluate`, providing the node's inputs) and decrypts operands
  (`Runtime.Decrypt`) through blocking calls returning `helium.OperandRef` handles. A node takes part
  only in the circuits and protocols its `Main` requests: the coordination events of a circuit or
  protocol in which the node has a role are held until the matching `Runtime` call.
- The `helper` package: the helper-assisted setting, with `helper.Server` (the helper node),
  `helper.Client` (a peer node), `helper.RunServer`/`helper.RunClient`, and the setting's
  configuration (`helper.Config`, `NodeList`, `NodeInfo`, `NodeAddress`, `TLSConfig`). It also hosts the
  protobuf translation layer, which the `api` package no longer provides.
- The `node` package: the node-side runtime shared by all settings. It implements
  `helium.Runtime` over the two runners (`node.New`), holds the rendez-vous gate between the
  application and the coordination events, and exposes `node.Starter` for the setting-specific
  package to start circuits and protocols.
- The `heliumtest` package: the local test fixtures (`Sessions` with their key material,
  `KeyProvider`, the `Circuits` test library, a local circuit `Runtime` and `CheckSetup`),
  usable both by applications and by the framework's own tests.
- The `protocols.Runner` type: a state machine executing the MHE protocols (in the aggregator,
  participant and receiver roles) as driven by the events of a `protocols.Coordinator`, and holding
  the protocols' results (fetched lazily from the aggregator when not available locally).
- The `protocols.CentralCoordinator` type: the coordination decisions (participant selection,
  retries, multi-round protocols) and the event log of the helper-assisted setting.
- The `protocols.Executing` event, published by a protocol's aggregator when it is ready to receive
  shares; participants send their share only after this event.
- The `protocols.KeyProvider` view, returning the setup keys from a `protocols.Runner`.
- The `coordinator.Log` generic event log.
- The `circuits.Runner` type: a state machine evaluating circuits as protocols between the
  input-providing nodes and an evaluator (`Started` → `Executing` → inputs → `Completed`), driven by
  the events of a `circuits.Coordinator`, and holding the outputs (fetched lazily from the evaluator).
- The `helium.Interface` type describing a circuit's inputs, summed inputs, outputs and required
  keys; it is either declared explicitly (`helium.Circuit.Interface`) or derived by symbolic execution
  of the evaluation function (`helium.Parse`, `helium.FromFunc`): the function is run end to end
  with placeholder ciphertexts and a recording evaluator, from which the required relinearization
  and Galois keys are inferred.
- The `helium.Evaluator` interface: Lattigo's `he.Evaluator` extended with scheme-agnostic
  key-switching operations (`Rotate`, `Conjugate`, `Automorphism`, `InnerSum`, `Replicate`), so that
  the required keys can be inferred; `Scheme` gives access to the underlying `bgv`/`ckks` evaluator.
- The `helium.OperandID` type: system-wide operand ids of the form `//<node>/<circuit-id>/<name>`,
  resolved once from a descriptor and an interface (`helium.Resolve`).
- The `protocols.Runner.DecryptOutput` method, returning the plaintext output of a decryption protocol to its target.

### Changed

- The package graph is inverted: `helium` is now the lowest-level package, holding the session
  vocabulary (`NodeID`, `SessionID`, `CircuitID`, `Parameters`, `Session`, `Secrets`,
  `PublicKeyProvider` and the key stores) and the whole circuit-definition language (`Circuit`,
  `CircuitRuntime`, `Evaluator`, `Signature`, `Descriptor`, `Port`, `Keys`, `Interface`, `Operand`,
  `Parse`, `Resolve`), plus the application contracts (`App`, `Runtime`, `Config`,
  `SetupDescription`). The runners (`protocols`, `circuits`), the node runtime (`node`) and the
  setting (`helper`) import it. As a result, an application imports `helium` and `helper` only,
  instead of the five packages it previously needed.
- Circuits are now pure functions from encrypted inputs to encrypted outputs: `CircuitRuntime.Output`
  replaces `NewOperand`/`EvalLocal`/`DEC`/`PCKS`, `CircuitRuntime.Evaluator` returns an evaluator with
  the declared keys, and intermediate values are plain ciphertexts. The decryption of an output is
  requested by the application through `Runtime.Decrypt`.
- `Server.Run` and `Client.Run` (and `helper.RunServer`/`helper.RunClient`) now run the app's `Main`
  and return once the node is done; the input provider argument, the `cdescs`/`outs` channels and the
  client-side circuit evaluation request are removed.
- The `circuits.InputProvider` is called with the ids of the operands the node must provide; it is
  now a runner-level mechanism fed by `Runtime.Evaluate`.
- `circuits.Runner.AwaitCompleted` returns an error when the circuit has failed.
- `helium.Config` holds the setting-independent node configuration (`ID`, `SessionParameters`,
  `MaxParticipation`, `MaxEvaluation`, `ObjectStore`); `helper.Config` embeds it and adds `HelperID`,
  `MaxProtoPerNode` and `TLS`. The runner configuration structs are no longer part of the
  user-facing configuration.
- The `NodeEvent` protobuf message is now a `oneof` of `ProtocolEvent` and `CircuitEvent`.
- `Client.Connect` no longer blocks until the connection to the helper is established: it creates
  the connection, which grpc establishes lazily. A node started before the helper now waits for it
  when opening the coordination stream, in `Client.Run`, bounded by the context passed to it, and
  this is also where an unreachable helper is reported. The `ClientConnectTimeout` constant is
  removed. `Client.Connect` resolves the helper's address through grpc; `ConnectWithDialer`, for
  in-memory connections, passes it to the dialer unresolved.

### Removed

- The `sessions` package: its contents moved to `helium`, except the test fixtures, which moved to
  `heliumtest` (`TestSession` is now `heliumtest.Sessions`, with its `HelperSession`/`NodeSessions`
  fields renamed to `Helper`/`Nodes`).
- The session and circuit ids carried in contexts (`sessions.NewContext`, `NewBackgroundContext`,
  the `Ctx*` keys and the `FromContext` accessors), which nothing read: an application now passes
  any context to `Run`. The gRPC metadata carries the sender's node id and the phase tag only.
- The `api` package (`api/pb` remains): the protobuf translation layer moved to `helper`.
- The old `node` package, the `setup.Service` (and its key backend), the `protocols.Executor` and
  `protocols.CompleteMap` types, and the `coordinator.TestCoordinator` type.
- The `services` packages: `services/compute` is replaced by the `circuits.Runner` type.
- The `sessions.Ciphertext` type, replaced by `helium.Operand`.

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
