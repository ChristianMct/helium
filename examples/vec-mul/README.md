# Example: 4-party vector multiplication

This package implements a 4-party vector multiplication as an example of Helium's usage.
It contains a Go application that starts an app over a node configured with a 4-nodes session.
The go application takes the node id and private input from the command line arguments. The 
private input is a single unsigned integer value that is copied n times to produce a vector
input of size n. It outputs the computation result, the component-wise product of the private
vectors, on stdout.

## Usage (Docker)

To build the example using Docker (requires no Go installation), navigate to this directory and run:
```
make docker
```
Then, to run the nodes:
```
docker compose up
```

## Usage (Go)

To build the example using Go, navigate to this directory and run:
```
make build
```
This compiles an executable `vec-mul` in the directory. Run `./vec-mul` for the usage.
