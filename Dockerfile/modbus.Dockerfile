# Modbus client/server image of the testbed (loriringhio97/modbus), rebuilt
# from the build history of the published image. Build from the repository root:
#   docker build -f Dockerfile/modbus.Dockerfile -t loriringhio97/modbus .
FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive
ARG PYMODBUS_VERSION=3.6.9
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash ca-certificates iproute2 iputils-ping net-tools openssh-client \
        openssh-server passwd procps python-is-python3 python3 python3-pip sed \
    && python -m pip install --no-cache-dir --upgrade pip setuptools wheel \
    && python -m pip install --no-cache-dir "pymodbus[serial,tls]==${PYMODBUS_VERSION}" \
    && mkdir -p /run/sshd \
    && ssh-keygen -A \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
CMD ["/bin/bash"]
