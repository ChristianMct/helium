#!/bin/bash

BASE_LABEL="com.docker-tc"

log() {
    echo "[$(date -Is)] [$CONTAINER_ID] $*"
}

QDISC_ID=
QDISC_HANDLE=
tc_init() {
    QDISC_ID=1
    QDISC_HANDLE="root handle $QDISC_ID:"
}
qdisc_del() {
    tc qdisc del dev "$1" root
}

qdisc_next() {
    QDISC_HANDLE="parent $QDISC_ID: handle $((QDISC_ID+1)):"
    ((QDISC_ID++))
}

# Following calls to qdisc_netm and qdisc_tbf are chained together
# http://man7.org/linux/man-pages/man8/tc-netem.8.html
qdisc_netm() {
    IF="$1"
    shift
    tc qdisc add dev "$IF" $QDISC_HANDLE netem $@
    qdisc_next
}

# http://man7.org/linux/man-pages/man8/tc-tbf.8.html
qdisc_tbf() {
    IF="$1"
    shift
    tc qdisc add dev "$IF" $QDISC_HANDLE tbf burst 5kb latency 50ms $@
    qdisc_next
}

docker_container_is_running() {
    docker ps --format '{{ .ID }}|{{ .Names }}|' | grep -q "$1|"
}

docker_container_get_networks() {
    docker inspect \
        --format '{{ json .NetworkSettings.Networks }}' \
        "$1" | \
        jq -r '. | keys | join("\n")'
}

docker_container_get_id() {
    docker inspect --format '{{ .Id }}' "$1"
}

docker_container_get_short_id() {
    docker_container_get_id "$1" | head -c 12
}

docker_container_get_name() {
    docker inspect --format '{{ .Name }}' "$1"
}

docker_container_get_interfaces() {
    IFLINKS=$(docker exec $1 sh -c 'cat /sys/class/net/*/iflink')
    if [ -z "$IFLINKS" ]; then
        return 1
    fi
    RESULT=""
    while IFS= read -r IFLINK; do
        if [[ "$IFLINK" -gt "1" ]]; then
            IFACE=$(grep -l $IFLINK /sys/class/net/veth*/ifindex | sed -e 's;^.*net/\(.*\)/ifindex$;\1;')
            if [ -n "$IFACE" ]; then
                RESULT+="${IFACE}\n"
            fi
        fi
    done < <(echo -e "$IFLINKS")
    echo "${RESULT::-2}"
}

docker_network_get_interfaces() {
    NETWORK_ID=$(docker network inspect --format '{{ .Id }}' "$1")
    SHORT_NETWORK_ID=$(echo -n "$NETWORK_ID" | head -c 12)
    NETWORK_INTERFACE_NAMES=$(ip a | grep -E "veth.*br-$SHORT_NETWORK_ID" | grep -o 'veth[^@]*' || :)
    if [ -z "$NETWORK_INTERFACE_NAMES" ]; then
        return 1
    fi
    echo "$NETWORK_INTERFACE_NAMES"
}

docker_container_interfaces_in_network() {
    CONTAINER_INTERFACES=$(docker_container_get_interfaces "$1")
    NETWORK_INTERFACES=$(docker_network_get_interfaces "$2")
    COMMON_INTERFACES=""
    while IFS= read -r NETWORK_IFACE; do
        while IFS= read -r CONTAINER_IFACE; do
            if [ "$NETWORK_IFACE" = "$CONTAINER_IFACE" ]; then
                COMMON_INTERFACES+="${CONTAINER_IFACE}\n"
            fi
        done < <(echo -e "$CONTAINER_INTERFACES")
    done < <(echo -e "$NETWORK_INTERFACES")
    echo "${COMMON_INTERFACES::-2}"
}


shape_traffic() {
    CONTAINER_NAME="$1"
    LIMIT="$2"
    DELAY="$3"

    if [[ ! -z "$2" ]]; then
        LIMIT="rate $2"
    fi
    if [[ ! -z "$3" ]]; then
        DELAY="delay $3"
    fi

    if [ -z "$CONTAINER_NAME" ]; then
        log "Error: Invalid payload"
    else
        # docker events
        #CONTAINER_ID=$(docker_container_get_short_id "$CONTAINER_ID")
        CONTAINER_ID=$(docker ps -aqf "name=$CONTAINER_NAME")
    fi

    NETWORK_NAMES=$(docker_container_get_networks "$CONTAINER_ID")
    if [[ "$NETWORK_NAMES" == *"\n"* ]]; then
        log "Warning: Container is connected to multiple networks"
    fi
    while read NETWORK_NAME; do
        NETWORK_INTERFACE_NAMES=$(docker_container_interfaces_in_network "$CONTAINER_ID" "$NETWORK_NAME")
        if [ -z "$NETWORK_INTERFACE_NAMES" ]; then
            log "Warning: Network has no corresponding virtual network interface"
            continue
        fi
        while IFS= read -r NETWORK_INTERFACE_NAME; do

            if [ ! -z "$LIMIT" ] || [ ! -z "$DELAY" ] ; then
                log "Set $LIMIT $DELAY on $NETWORK_INTERFACE_NAME"

                tc qdisc add dev $NETWORK_INTERFACE_NAME root netem $LIMIT $DELAY
            fi
            log "Controlling traffic of the container $(docker_container_get_name "$CONTAINER_ID") on $NETWORK_INTERFACE_NAME"
        done < <(echo -e "$NETWORK_INTERFACE_NAMES")
    done < <(echo -e "$NETWORK_NAMES")
}

shape_traffic "$1" "$2" "$3"

