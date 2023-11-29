#########################################
#  Builder                              #
#########################################
FROM golang:1.20.1 as builder


WORKDIR /helium

COPY go.mod ./
COPY go.sum ./

RUN go mod download

COPY pkg ./pkg
COPY apps ./apps

RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 go build -v ./apps/node

#########################################
#  Image                                #
#########################################
FROM ubuntu:latest

WORKDIR /helium

# RUN apk add --no-cache bash
# RUN apk add --no-cache iproute2-tc
# RUN apk add --no-cache iperf3
# RUN apk add --no-cache git

RUN apt update
RUN apt install -y iperf3 git iproute2

COPY deployment/apps/shape_egress_and_start.sh /helium/shape_egress_and_start.sh
#COPY deployment/apps/shape_ingress_traffic.sh /helium/shape_ingress_traffic.sh
COPY --from=builder /helium/node /helium/node

#RUN mkdir /lib64 && ln -s /lib/libc.musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2

EXPOSE 40000

ENTRYPOINT [ "/helium/node" ]
