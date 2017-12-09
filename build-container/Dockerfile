FROM debian:stretch

RUN apt-get update && \
	apt-get install -y g++ cmake zlib1g-dev libboost-system-dev libboost-program-options-dev libpthread-stubs0-dev libfuse-dev git && \
	apt-get clean && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /build /work
COPY build.sh /build
RUN chmod 755 /build/build.sh

VOLUME /work
WORKDIR /work
