FROM ubuntu:18.04

RUN apt-get update && apt-get install -y python3 cmake build-essential cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev git

ENV ZEEK_VERSION v3.0.1

# Build Zeek
WORKDIR /build
RUN git clone --recursive --branch $ZEEK_VERSION https://github.com/zeek/zeek

RUN apt-get update && apt-get install -y ninja-build
RUN cd /build/zeek && ./configure --generator=Ninja
RUN cd /build/zeek && ninja -C build
RUN cd /build/zeek && ninja -C build install

# Copy in module, and rebuild zeek

COPY . /build/zeek/src/analyzer/protocol/eniplg
RUN cd /build/zeek && ./configure --generator=Ninja
RUN cd /build/zeek && ninja -C build
RUN cd /build/zeek && ninja -C build install

ENTRYPOINT [ "/zeek/bin/zeek" ]