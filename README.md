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
Helium's two main types are:
- The `node.App` type which lets the user define an application by specifying the circuits to be run.
- The `node.Node` type which runs `node.App` applications by running the MHE setup phase and letting the user trigger circuit evaluations.

Here is an overview of an Helium application:
```go
  // declares an helium application
  app = node.App{

    // describes the required MHE setup
    SetupDescription: &setup.Description{ Cpk: true, Rlk: true},
    
    // declares the application's circuits
    Circuits: map[circuits.Name]circuits.Circuit{
      "mul-2-dec": func(rt circuits.Runtime) error {
        in0, in1 := rt.Input("//p0/in"), rt.Input("//p1/in") // read the encrypted inputs from nodes p0 and p1

        // multiplies the inputs as a local operation
        opRes := rt.NewOperand("//eval/prod")
        if err := rt.EvalLocal(
          true, // circuit requires relin
          nil,  // circuit does not require any rotation
          func(eval he.Evaluator) error {
					  return eval.MulRelin(in0.Get().Ciphertext, in1.Get().Ciphertext,  opRes.Ciphertext)
				  }
        ); err != nil {
					return err
				}

        // decrypts the result with receiver "rec"
        return rt.DEC(opRes, "rec", map[string]string{
          "smudging": "40.0",
        })
      },
    },
  }

  inputProvider = func(ctx context.Context, cid helium.CircuitID, ol circuits.OperandLabel, sess session.Session) (any, error) {
      // ... user-defined logic to provide input for a given circuit
  }

  ctx, config, nodelist := // ... (omitted config, usually loaded from files or command-line flags)

  n, cdescs, outputs, err := node.RunNew(ctx, config, nodelist, app, inputProvider) // create an helium node that runs the app
  if err != nil {
    log.Fatal(err)
  }

  // cdesc is a channel to send circuit evaluation request(s)
  cdescs <- circuits.Descriptor{
    Signature:   circuits.Signature{Name: circuits.Name("mul-4-dec")}, // evaluates circuit "mul-4-dec"
    CircuitID:   "mul-4-dec-0",                                        // as circuit  "mul-4-dec-0"
    // ... other runtime-specific info 
  }

  // outputs is a channel to recieve the evaluation(s) output(s)
  out <- outputs 
  // ... 
```

A complete example application is available in the [examples](/examples/vec-mul/) folder.

## Features
The framework currently supports the following features:
- N-out-of-N-threshold and T-out-of-N-threshold
- Helper-assisted setting
- Setup phase for any multiparty RLWE scheme suppported by Lattigo, compute phase for BGV.
- Circuit evaluation with output to the input-parties (internal) and to the helper (external).

Current limitations:
- This release does not fully implement the secure failure-handling mechanism of the Helium paper. The full implementation is currently being cleaned up
and requires changes to the Lattigo library.
- In the T-out-of-N setting, Helium assumes that the secret-key generation is already performed and that the user provides the generated secret-key.
Implementing this phase in the framework is planned.
- Altough supported by the MHE scheme, external computation-receiver other than the helper (ie., re-encryption under arbitrary public-keys) are not yet supported.
Supporting this feature is expected soon as it is rather easy to implement.
- The current version of Helium targets a proof of concept for lightweight MPC in the helper-assisted model. Altough most of the low-level code is already 
generic enough to support peer-to-peer applications, some more work on the high-level node implementation would be required to support fully it.

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
@article{mouchet2024helium,
  title={Helium: Scalable MPC among Lightweight Participants and under Churn},
  author={Mouchet, Christian and Chatel, Sylvain and Pyrgelis, Apostolos and Troncoso, Carmela},
  journal={Cryptology ePrint Archive},
  year={2024}
}
```
