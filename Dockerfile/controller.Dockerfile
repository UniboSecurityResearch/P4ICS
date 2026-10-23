# P4ICS controller (controller/): the optional P4Runtime control plane, for
# the Kathara lab of controller/lab/. Build from the repository root:
#   docker build -f Dockerfile/controller.Dockerfile -t loriringhio97/p4ics-controller .
FROM golang:1.25.6-bookworm AS build
WORKDIR /src
COPY controller/go.mod controller/go.sum ./
RUN go mod download
COPY controller/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags=-s -o /p4ics-controller ./cmd/p4ics-controller

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl iproute2 \
    iputils-ping openssl procps \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /p4ics-controller /usr/local/bin/p4ics-controller
COPY controller/pki.sh /usr/local/bin/p4ics-pki
COPY controller/lab/api.sh /usr/local/bin/p4ics-api
