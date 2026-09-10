<p align="center">
	<img src="images/helium_logo.png" />
</p>

# Helium

Helium is a secure multiparty computation (MPC) framework based on multiparty homomorphic encryption (MHE). 
The framework provides an interface for computing multiparty homorphic circuits and takes care of executing the necessary MHE protocols under the hood.
It uses the [Lattigo library](https://github.com/tuneinsight/lattigo) for the M(HE) operations, and provides a built-in network transport layer based on
[gRPC](https://grpc.io).
The framework currently supports the helper-assisted setting, where the parties in the MPC receive assistance from honest-but-curious server.
The system and its operating principles are described in the paper: [Helium: Scalable MPC among Lightweight Participants and under Churn](https://eprint.iacr.org/2024/194).

**Disclaimer**: this is an highly experiental first release, aimed at providing a proof-of-concept. 
The code is expected to evolve without guaranteeing backward compatibility and it should not be used in a production setting.

## Synopsis
Helium is a Go package that provides the types and methods to implement an end-to-end MHE application.
Helium's main types are:
- The `helium.App` type which lets the user define an application by specifying the required MHE setup, the circuits, and the `Main` function run by every node.
- The `helium.Runtime` type, the interface of the framework available to `Main`: it evaluates circuits and runs decryption protocols, blocking until they have completed. A node takes part only in the circuits and protocols its `Main` requests.
- The `helium.HeliumServer` (helper node) and `helium.HeliumClient` (peer node) types which run `helium.App` applications: they run the MHE setup phase, then the application's `Main`.
- Under the hood, two engines drive the nodes as state machines: `protocols.MHEMPC` executes the MHE protocols and `circuits.Engine` evaluates the circuits, both driven by the coordination events of the helper's `protocols.CentralCoordinator`.

A circuit is a Go function mapping encrypted input operands to encrypted output operands. Its inputs, outputs and required
evaluation keys form its interface, which is either declared explicitly or derived by symbolic execution of the function:
the function is run with placeholder ciphertexts and a recording evaluator, from which the required relinearization and
Galois keys are inferred.
Here is an overview of an Helium application:
```go
  // declares an helium application
  app = helium.App{

    // describes the required MHE setup
    SetupDescription: &helium.SetupDescription{ Cpk: true, Rlk: true},
    
    // declares the application's circuits
    Circuits: map[circuits.Name]circuits.Circuit{
      "mul-2": circuits.FromFunc(func(rt circuits.Runtime) error {
        in0, in1 := rt.Input("//p0/in"), rt.Input("//p1/in") // the encrypted inputs of parties p0 and p1
        out := rt.Output("prod")                              // the encrypted output, owned by the evaluator

        // multiplies the inputs (the relinearization key is inferred from the use of MulRelinNew)
        res, err := rt.Evaluator().MulRelinNew(in0.Get().Ciphertext, in1.Get().Ciphertext)
        if err != nil {
          return err
        }
        out.Set(res)
        return nil
      }),
    },

    // the application's logic, run by every node
    Main: func(ctx context.Context, rt *helium.Runtime) error {
      // the evaluation of the circuit "mul-2" as "mul-2-0", by the helper, with p0 and p1 mapped to actual nodes
      cd := circuits.Descriptor{
        Signature:   circuits.Signature{Name: "mul-2"},
        CircuitID:   "mul-2-0",
        NodeMapping: map[string]sessions.NodeID{"p0": "node-1", "p1": "node-2"},
        Evaluator:   "helper",
      }

      // the peers provide their input "in" (the helper has none); the call blocks until the circuit has completed
      var inputs map[string]any
      if rt.ID() != "helper" {
        inputs = map[string]any{"in": []uint64{ /* ... */ }}
      }
      outs, err := rt.Evaluate(ctx, cd, inputs)

      // the decryption of the output "prod" to the helper, with 40 bits of smudging noise; the peers
      // take part in the protocol, the helper obtains the plaintext
      pt, err := rt.Decrypt(ctx, outs["prod"], "helper", 40)
      if rt.ID() == "helper" {
        // ... decodes pt, a Lattigo plaintext
      }
      return err
    },
  }

  ctx, config, nodelist := // ... (omitted config, usually loaded from files or command-line flags)

	if nodeID == helperID {
    // the helper runs the server-side of helium; the call returns once Main has returned and the coordination is done
		hsv, err := helium.RunHeliumServer(ctx, config, nodelist, app)
	} else {
    // non-helper nodes run the client side; the call returns once Main has returned and the helper has terminated
		hc, err := helium.RunHeliumClient(ctx, config, nodelist, secrets, app)
	}
```

A complete example application is available in the [examples](/examples/vec-mul/) folder.

## Features
The framework currently supports the following features:
- N-out-of-N-threshold and T-out-of-N-threshold
- Helper-assisted setting
- Setup phase for any multiparty RLWE scheme suppported by Lattigo, compute phase for BGV and CKKS.
- Circuit evaluation and decryption of the outputs to the input-parties (internal) and to the helper (external).

Current limitations:
- This release does not fully implement the secure failure-handling mechanism of the Helium paper. The full implementation is currently being cleaned up
and requires changes to the Lattigo library.
- In the T-out-of-N setting, Helium assumes that the secret-key generation is already performed and that the user provides the generated secret-key.
Implementing this phase in the framework is planned.
- Altough supported by the MHE scheme, external computation-receiver other than the helper (ie., re-encryption under arbitrary public-keys) are not yet supported.
Supporting this feature is expected soon as it is rather easy to implement.
- The current version of Helium targets a proof of concept for lightweight MPC in the helper-assisted model. The protocol and circuit engines are
agnostic of the network topology and derive the nodes' roles from the protocol and circuit descriptors; supporting peer-to-peer applications
requires a coordinator and a transport for that setting.

Roadmap: to come.

## MHE-based MPC

Helium currently supports the MHE scheme and associated MPC protocol described in the paper ["Multiparty Homomorphic Encryption from Ring-Learning-With-Errors"](https://eprint.iacr.org/2020/304.pdf) along with its extension to t-out-of-N-threshold encryption described in ["An Efficient Threshold Access-Structure for RLWE-Based Multiparty Homomorphic Encryption"](https://eprint.iacr.org/2022/780.pdf). These schemes provide security against passive attackers that can corrupt up to t-1 of the input parties and can operate in various system models such as peer-to-peer, cloud-assisted or hybrid architecture.

The protocol consists in 2 main phases, the **Setup** phase and the **Computation** phase, as illustrated in the diagram below. 
The Setup phase is independent of the inputs and can be performed "offline".
Its goal is to generate a collective public-key for which decryption requires collaboration among a parameterizable threshold number of parties.
In the Computation phase, the parties provide their inputs encrypted under the generated collective key.
Then, the circuit is homomorphically evaluated and the output is collaboratively re-encrypted to the receiver secret-key.

## Issues & Contact

Please make use of Github's issue tracker for reporting bugs or ask questions. 
Feel free to contact me if you are interested in the project and would like to contribute. My contact email should be easy to find.

## Citing Helium
```
@inproceedings{mouchet2024helium,
  title={Helium: Scalable MPC among lightweight participants and under churn},
  author={Mouchet, Christian and Chatel, Sylvain and Pyrgelis, Apostolos and Troncoso, Carmela},
  booktitle={Proceedings of the 2024 on ACM SIGSAC Conference on Computer and Communications Security},
  pages={3038--3052},
  year={2024}
}
```
