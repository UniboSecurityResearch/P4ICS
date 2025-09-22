FROM python:3.12-alpine

RUN apk add --no-cache bash

RUN pip3 install paho-mqtt