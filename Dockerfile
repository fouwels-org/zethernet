
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

# Copy in module
COPY . /build/zeek/src/analyzer/protocol/eniplg
COPY ./dpd.sig /build/zeek/scripts/base/protocols/eniplg/dpd.sig
COPY ./main.zeek /build/zeek/scripts/base/protocols/eniplg/main.zeek
COPY ./__load__.zeek /build/zeek/scripts/base/protocols/eniplg/__load__.zeek
RUN echo "add_subdirectory(eniplg)" >> /build/zeek/src/analyzer/protocol/CMakeLists.txt
RUN echo "@load base/protocols/eniplg" >> /build/zeek/scripts/base/init-default.zeek


# Rebuild Zeek
RUN cd /build/zeek && ./configure --generator=Ninja
RUN cd /build/zeek && ninja -C build all
RUN cd /build/zeek && ninja -C build install

COPY ./tests/ /tests/

ENTRYPOINT [ "/usr/local/zeek/bin/zeek" ]