# DNP3 outstation (protocols/dnp3/server_tcp) and master (client_tcp) for the
# Kathara testbed. Build from the repository root:
#   docker build -f Dockerfile/dnp3.Dockerfile -t loriringhio97/dnp3 .
# The TLS variants need certificates that are not in the repository.
FROM rust:1.99.1-bookworm AS build
WORKDIR /src
COPY protocols/dnp3/server_tcp server_tcp
COPY protocols/dnp3/client_tcp client_tcp
RUN cargo build --release --manifest-path server_tcp/Cargo.toml \
 && cargo build --release --manifest-path client_tcp/Cargo.toml

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 net-tools iputils-ping \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/server_tcp/target/release/server_tcp /usr/local/bin/dnp3_server
COPY --from=build /src/client_tcp/target/release/client_tcp /usr/local/bin/dnp3_client
WORKDIR /root
