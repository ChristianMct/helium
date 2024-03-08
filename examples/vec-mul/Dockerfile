#########################################
#  Builder                              #
#########################################
FROM golang:1.22 as builder

ARG APP=examples/vec-mul/

WORKDIR /helium

COPY go.mod ./
COPY go.sum ./

RUN go mod download

COPY pkg ./pkg
COPY ${APP} ./app/

RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 go build -v -o node ./app 

#########################################
#  Image                                #
#########################################
FROM scratch

WORKDIR /helium

COPY --from=builder /helium/node /helium/node

EXPOSE 40000

ENTRYPOINT [ "/helium/node" ]
