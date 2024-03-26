FROM eclipse-mosquitto:2.0

RUN apk add --no-cache bash

ENTRYPOINT /bin/bash