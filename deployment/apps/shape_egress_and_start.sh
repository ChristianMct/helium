#!/bin/bash

interface='eth0'

rate=
delay=

if [[ ! -z "${RATE_LIMIT}" ]]; then
    rate="rate ${RATE_LIMIT}"
fi
if [[ ! -z "${DELAY}" ]]; then
    delay="delay ${DELAY}"
fi

if [[ -n "${RATE_LIMIT}" ]] || [[ -n "${DELAY}" ]]; then
    echo "Applying network condition $rate $delay"

    # apply egress traffic rate limit
    tc qdisc add dev $interface root netem $delay $rate || exit 1
else
    echo "No network condition applied"
fi

/helium/node $@
