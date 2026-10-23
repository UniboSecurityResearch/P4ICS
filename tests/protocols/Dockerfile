# bmv2 + the real industrial stacks of the testbed, to run them through two
# P4ICS switches in one container (tests/protocols/run_protocols.sh).
ARG P4_IMAGE=loriringhio97/p4@sha256:4ecf4ad5c433ff214f076ad06d051c2c9b5b9394bb6dfc0bb81a102b53fff5f2
FROM loriringhio97/dnp3:latest AS dnp3

FROM ${P4_IMAGE}
COPY --from=dnp3 /usr/local/bin/dnp3_server /usr/local/bin/dnp3_client /usr/local/bin/
RUN pip install --no-cache-dir --break-system-packages pymodbus==3.6.9 cpppo==5.2.5
