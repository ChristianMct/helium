#########################################
#  Builder                              #
#########################################
FROM golang:1.18 as builder


WORKDIR /helium

COPY go.mod ./
COPY go.sum ./

RUN go mod download

COPY pkg ./pkg
COPY apps ./apps

RUN go build ./apps/node

#########################################
#  Image                                #
#########################################
FROM alpine:3.15

WORKDIR /helium

COPY --from=builder /helium/node /helium/node

RUN mkdir /lib64 && ln -s /lib/libc.musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2

EXPOSE 40000

ENTRYPOINT [ "/helium/node" ]
