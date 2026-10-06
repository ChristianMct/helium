// Command gencerts generates a self-signed certificate authority and one
// certificate per node, laid out as the helper.TLSConfig FromDirectory option
// expects: ca.crt, <node-id>.crt and <node-id>.key.
//
// It is meant for tests and development deployments. A production deployment is
// expected to issue the node certificates from its own PKI; the only requirement
// Helium makes is that a node's certificate carries its node id as a dNSName SAN,
// and chains to the CA that the other nodes are configured with.
//
// Usage:
//
//	go run ./examples/gencerts -out ./certs helper node-1 node-2 node-3 node-4
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/ChristianMct/helium/utils/certs"
)

func main() {
	outDir := flag.String("out", "certs", "the directory to write the certificates to")
	validity := flag.Duration("validity", 365*24*time.Hour, "the validity period of the certificates")
	flag.Parse()

	nodeIDs := flag.Args()
	if len(nodeIDs) == 0 {
		log.Fatal("no node id given: pass the node ids as arguments, e.g. gencerts helper node-1")
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		log.Fatalf("could not create %s: %v", *outDir, err)
	}

	ca, err := certs.NewAuthority("helium-ca", *validity)
	if err != nil {
		log.Fatalf("could not create the CA: %v", err)
	}
	write(*outDir, "ca.crt", ca.CertPEM, 0o644)

	for _, nodeID := range nodeIDs {
		certPEM, keyPEM, err := ca.Issue(nodeID, *validity)
		if err != nil {
			log.Fatalf("could not issue a certificate for %s: %v", nodeID, err)
		}
		write(*outDir, fmt.Sprintf("%s.crt", nodeID), certPEM, 0o644)
		write(*outDir, fmt.Sprintf("%s.key", nodeID), keyPEM, 0o600)
	}

	log.Printf("wrote the CA and %d node certificates to %s", len(nodeIDs), *outDir)
}

func write(dir, name string, data []byte, perm os.FileMode) {
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, perm); err != nil {
		log.Fatalf("could not write %s: %v", path, err)
	}
}
