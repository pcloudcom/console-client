FROM alpine:latest

RUN apk add --no-cache boost zlib fuse tini

RUN apk add --no-cache --virtual build-dependencies cmake \
  boost g++ make fuse-dev zlib-dev boost-dev git && \
  git clone https://github.com/mwiget/console-client.git && \
  cd console-client && cmake pCloudCC && \
  make && make install && \
  apk del build-dependencies && cd .. && rm -rf console-client

ENTRYPOINT ["/sbin/tini", "/usr/local/bin/pcloudcc"]
