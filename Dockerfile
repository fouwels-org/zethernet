# SPDX-FileCopyrightText: 2020 Kaelan Thijs Fouwels <kaelan.thijs@fouwels.com>
#
# SPDX-License-Identifier: MIT

FROM ubuntu:impish-20220105 as build

RUN apt-get update && apt-get install -y python3 cmake build-essential cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev git

ENV ZEEK_VERSION v3.2.4

# Build Zeek
WORKDIR /build
RUN git clone --depth 1 --recursive --branch $ZEEK_VERSION https://github.com/zeek/zeek

RUN apt-get update && apt-get install -y ninja-build
RUN cd /build/zeek && ./configure --enable-debug --generator=Ninja
RUN cd /build/zeek && ninja -C build && ninja -C build install

# Copy in module
COPY . /build/zeek/src/analyzer/protocol/eniplg
COPY ./scripts/. /build/zeek/scripts/base/protocols/eniplg
RUN echo "add_subdirectory(eniplg)" >> /build/zeek/src/analyzer/protocol/CMakeLists.txt
RUN echo "@load base/protocols/eniplg" >> /build/zeek/scripts/base/init-default.zeek

# Rebuild Zeek
RUN cd /build/zeek && ./configure --enable-debug --generator=Ninja
RUN cd /build/zeek && ninja -C build && ninja -C build install

#RUN setcap cap_net_raw,cap_net_admin,cap_dac_override+eip /usr/local/zeek/bin/zeek

FROM ubuntu:impish-20220105
RUN apt-get update && apt-get install -y libpcap-dev libssl-dev zlib1g-dev 
COPY --from=build /usr/local/zeek/ /usr/local/zeek/
COPY ./test-files/ /test-files/
ENTRYPOINT [ "/usr/local/zeek/bin/zeek" ]