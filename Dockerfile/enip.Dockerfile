# EtherNet/IP (CIP) server and client of protocols/Ethernet-IP, based on cpppo,
# for the Kathara testbed. Build from the repository root:
#   docker build -f Dockerfile/enip.Dockerfile -t loriringhio97/enip .
FROM python:3.11-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 net-tools iputils-ping \
 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir cpppo==5.2.5
COPY protocols/Ethernet-IP /enip
WORKDIR /enip
