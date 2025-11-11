FROM alpine:latest

RUN mkdir -p /bacnet
WORKDIR /bacnet

RUN apk add --no-cache git build-base linux-headers

RUN git clone https://github.com/bacnet-stack/bacnet-stack.git

RUN rm -rf bacnet-stack/apps/server-basic \
    && rm -rf bacnet-stack/apps/server-client

WORKDIR /bacnet/bacnet-stack/apps

COPY server-basic ./server-basic/
COPY server-client ./server-client/

WORKDIR /bacnet/bacnet-stack

RUN make || true

CMD ["sh"]