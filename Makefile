# SPDX-FileCopyrightText: 2020 Kaelan Thijs Fouwels <kaelan.thijs@fouwels.com>
#
# SPDX-License-Identifier: MIT

COMPOSE=docker compose
BUILDFILE=compose.yml
DOCKER=docker

# Docker
build: 
	$(COMPOSE) -f $(BUILDFILE) build
push:
	$(COMPOSE) -f $(BUILDFILE) push
up:
	$(COMPOSE) -f $(BUILDFILE) up
up-d:
	$(COMPOSE) -f $(BUILDFILE) up -d

# Local

# Update Zeek root to match your root zeek install location
ZEEK_ROOT=~/proj/zeek
OUTPUT_DIR=~/proj/zeek-install

# Dependencies
dep-local:
	apt-get update && apt-get install -y python3 cmake build-essential cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev

# Module installation
install-module-local: install-scripts
	echo "add_subdirectory(eniplg)" >> $(ZEEK_ROOT)/src/analyzer/protocol/CMakeLists.txt
	echo "@load base/protocols/eniplg" >> $(ZEEK_ROOT)/scripts/base/init-default.zeek
install-scripts:
	rm -rf $(ZEEK_ROOT)/scripts/base/protocols/eniplg/ && cp -r ./scripts/. $(ZEEK_ROOT)/scripts/base/protocols/eniplg/

# Zeek
conf-local:
	cd $(ZEEK_ROOT) && ./configure --enable-debug --prefix=$(OUTPUT_DIR) --generator=Ninja	
build-local: install-scripts
	cd $(ZEEK_ROOT) &&  ninja -C build && ninja -C build install
allow:
	sudo setcap cap_net_raw,cap_net_admin,cap_dac_override+eip $(OUTPUT_DIR)/bin/zeek

# Testing
ZEEK_PARAMS = -r $(ZEEK_ROOT)/src/analyzer/protocol/eniplg/tests/lagoni/CLX5000_Download_RM.pcapng
run-local:
	cd $(OUTPUT_DIR) && ./bin/zeek $(ZEEK_PARAMS)