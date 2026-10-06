# Example: 4-party vector multiplication

This package implements a 4-party vector multiplication as an example of Helium's usage.
It contains a Go application that starts an app over a node configured with a 4-nodes session.
The go application takes the node id and private input from the command line arguments. The 
private input is a single unsigned integer value that is copied n times to produce a vector
input of size n. It outputs the computation result, the component-wise product of the private
vectors, on stdout.

The nodes authenticate each other with mutual TLS.

## Usage (Docker)

To build and run the whole example (requires no Go installation), navigate to this directory and run:
```
make run
```
This builds the image, generates a certificate authority and one certificate per node into a
`certs` volume, and then starts the nodes. Equivalently, `make docker` then `docker compose up`.

To tear the example down, including the generated certificates:
```
make down
```

## Usage (Go)

To build the example using Go, navigate to this directory and run:
```
make build
```
This compiles an executable `vec-mul` in the directory. Run `./vec-mul` for the usage.

Each node needs its TLS material before it can start. To generate it for all the nodes at once:
```
make certs
```
This writes `ca.crt` and a `<node-id>.crt` / `<node-id>.key` pair per node into `./certs`, which is
where the nodes look by default. Use `-certs <dir>` to point them elsewhere.

In a real deployment, the node certificates are issued by the deployment's own PKI: the only
requirement is that a node's certificate chains to the CA the other nodes are configured with, and
carries the node's id as a `dNSName` SAN.

## Running without TLS

Passing `-no-tls` to every node disables TLS. Node identities are then unauthenticated: any node can
claim to be any other, so this is for testing only.
