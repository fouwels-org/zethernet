COMPOSE=docker-compose
BUILDFILE=build.yml
DOCKER=docker

#Docker
build: 
	$(COMPOSE) -f $(BUILDFILE) build
push:
	$(COMPOSE) -f $(BUILDFILE) push
up:
	$(COMPOSE) -f $(BUILDFILE) up
up-d:
	$(COMPOSE) -f $(BUILDFILE) up -d

ZEEK_ROOT=../../../../

build-local:
	cd $(ZEEK_ROOT) && ./configure --enable-debug --prefix=./out --generator=Ninja && ninja -C build && ninja -C build install

run-local:
	cd $(ZEEK_ROOT)/out && ./bin/zeek