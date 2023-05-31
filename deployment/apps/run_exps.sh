#!/bin/bash

if [ -z "$1"  ] || [ -z "$2" ]
  then
    echo "Usage: $0 local|cluster cloud|clients|all"
    exit 1
fi

docker image pull heliummpc/helium

for exp in psi-2 psi-4 psi-8 pir-3 pir-5 pir-9
do
        docker compose --file scenarios/$exp/$1/docker-compose.yml --profile "$2" up
        sleep 1
        docker compose --file scenarios/$exp/$1/docker-compose.yml --profile "$2" down
        sleep 3
done