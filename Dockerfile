# SPDX-FileCopyrightText: 2020 Kaelan Thijs Fouwels <kaelan.thijs@fouwels.com>
#
# SPDX-License-Identifier: MIT

FROM ubuntu:impish-20220105 as build

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && \
    apt-get install -y python3 cmake build-essential cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev git && rm -rf /var/lib/apt/lists/*

ENV ZEEK_VERSION v3.2.4

# Build Zeek
WORKDIR /build
RUN git clone --depth 1 --recursive --branch $ZEEK_VERSION https://github.com/zeek/zeek

RUN cd /build/zeek && ./configure --enable-debug
RUN cd /build/zeek && make -j $(nproc) && make install

# Copy in module
COPY . /build/zeek/src/analyzer/protocol/eniplg
COPY ./scripts/. /build/zeek/scripts/base/protocols/eniplg
RUN echo "add_subdirectory(eniplg)" >> /build/zeek/src/analyzer/protocol/CMakeLists.txt
RUN echo "@load base/protocols/eniplg" >> /build/zeek/scripts/base/init-default.zeek

# Rebuild Zeek
RUN cd /build/zeek && ./configure --enable-debug
RUN cd /build/zeek && make -j $(nproc) && make install

FROM ubuntu:impish-20220105

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && \
    apt-get install -y libpcap-dev libssl-dev zlib1g-dev && rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/local/zeek/ /usr/local/zeek/
RUN ln -s /usr/local/zeek/bin/zeek /usr/local/bin/zeek

COPY ./test-files/ /test-files/

ENTRYPOINT [ "zeek" ]