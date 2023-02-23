#!/bin/sh
set -o errexit
set -o nounset

IFS=$(printf '\n\t')

DAYS=365000
sep=$(echo $(yes "=" | head -n10))

gen_creds() {
    echo "${sep}"

    identity=${1:-"yoda"}
    PRIV_KEY="${identity}.key"
    PUB_KEY="${identity}_pub.key"
    CERT="${identity}.crt"

    echo "Generating Private Key - ${PRIV_KEY}"
    openssl genpkey -algorithm ed25519 -out "${PRIV_KEY}"
    echo "Generating PubKey - ${PUB_KEY}"
    openssl pkey -in "${PRIV_KEY}" -pubout -out "${PUB_KEY}"

    export CN="${identity}"
    echo "Generating CSR"
    openssl req -new -out "${identity}.csr" -key "${PRIV_KEY}" -config openssl-25519.cnf -reqexts v3_req
    echo "Signing CSR ${CERT}"
    openssl x509 -req -days "${DAYS}" -in "${identity}.csr" -out "${CERT}" \
        -CA "CA.crt" -CAkey "CA.key" -set_serial 1000 -extfile openssl-25519.cnf -extensions v3_req

    openssl verify -verbose -CAfile "CA.crt"  "${CERT}"
    rm ./*.csr
    unset CN
}

gen_ca() {
  identity="CA"
  PRIV_KEY="${identity}.key"
  CERT="${identity}.crt"

  echo "Generating Private Key - ${PRIV_KEY}"
  openssl genpkey -algorithm ed25519 -out "${PRIV_KEY}"
  openssl req -new -x509 -nodes -days "${DAYS}" -key "${PRIV_KEY}" -out "${CERT}" -subj /C=CH/ST=ZU/L=SVL/O=gRPC/CN=ca_server \
    -addext "subjectAltName = DNS:ca_server,DNS:ca_server.com,DNS:www.ca_server.com"
}

clean() {
    rm ./*.csr ./*.key ./*.crt -rf ||:
}

clean
gen_ca
i=0
while [ $i -le 5 ]; do
    gen_creds "light-$i"
    gen_creds "helper-$i"
    gen_creds "full-$i"

    i=$(( i + 1 ))
done
gen_creds "node-a"
gen_creds "node-b"
