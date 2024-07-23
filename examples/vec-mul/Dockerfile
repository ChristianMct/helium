#########################################
#  Builder                              #
#########################################
FROM golang:latest AS builder

ARG APP=examples/vec-mul/

WORKDIR /helium

COPY go.mod ./
COPY go.sum ./

RUN go mod download

COPY . .
COPY ${APP} ./app/

RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 go build -v -o ./app/node ./app 

#########################################
#  Image                                #
#########################################
FROM scratch

WORKDIR /helium

COPY --from=builder /helium/app/node /helium/node

EXPOSE 40000

ENTRYPOINT [ "/helium/node" ]
