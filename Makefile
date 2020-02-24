COMPOSE=docker-compose
BUILDFILE=build.yml
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
ZEEK_ROOT=~/proj/zeek-sw
OUTPUT_DIR=~/proj/zeek-install

dep-local:
	apt-get update && apt-get install -y python3 cmake build-essential cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev

build-local:
	cd $(ZEEK_ROOT) && ./configure --enable-debug --prefix=$(OUTPUT_DIR) --generator=Ninja && ninja -C build && ninja -C build install

allow:
	sudo setcap cap_net_raw,cap_net_admin,cap_dac_override+eip $(OUTPUT_DIR)/bin/zeek

ZEEK_PARAMS = -i eth2 -B dpd
run-local:
	cd $(OUTPUT_DIR) && ./bin/zeek $(ZEEK_PARAMS)