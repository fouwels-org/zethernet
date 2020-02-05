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
