FROM debian:bullseye

RUN apt update && apt install -y iproute2 net-tools openjdk-17-jre inetutils-ping