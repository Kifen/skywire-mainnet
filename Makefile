.DEFAULT_GOAL := help
.PHONY : check lint install-linters dep test 
.PHONY : build  clean install  format  bin
.PHONY : host-apps bin 
.PHONY : run stop config
.PHONY : docker-image  docker-clean docker-network  
.PHONY : docker-apps docker-bin docker-volume 
.PHONY : docker-run docker-stop     

VERSION := $(shell git describe)

RFC_3339 := "+%Y-%m-%dT%H:%M:%SZ"
DATE := $(shell date -u $(RFC_3339))
COMMIT := $(shell git rev-list -1 HEAD)

PROJECT_BASE := github.com/SkycoinProject/skywire-mainnet
OPTS?=GO111MODULE=on
DOCKER_IMAGE?=skywire-runner # docker image to use for running skywire-visor.`golang`, `buildpack-deps:stretch-scm`  is OK too
DOCKER_NETWORK?=SKYNET 
DOCKER_NODE?=SKY01
DOCKER_OPTS?=GO111MODULE=on GOOS=linux # go options for compiling for docker container
TEST_OPTS?=-race -tags no_ci -cover -timeout=5m
TEST_OPTS_NOCI?=-race -cover -timeout=5m -v

BUILDINFO_PATH := $(PROJECT_BASE)/pkg/util/buildinfo

BUILDINFO_VERSION := -X $(BUILDINFO_PATH).version=$(VERSION)
BUILDINFO_DATE := -X $(BUILDINFO_PATH).date=$(DATE)
BUILDINFO_COMMIT := -X $(BUILDINFO_PATH).commit=$(COMMIT)

BUILDINFO?=-ldflags="$(BUILDINFO_VERSION) $(BUILDINFO_DATE) $(BUILDINFO_COMMIT)"

BUILD_OPTS?=$(BUILDINFO)

check: lint test ## Run linters and tests

build: dep host-apps bin ## Install dependencies, build apps and binaries. `go build` with ${OPTS} 

run: stop build	config  ## Run skywire-visor on host
	./skywire-visor skywire.json

stop: ## Stop running skywire-visor on host
	-bash -c "kill $$(ps aux |grep '[s]kywire-visor' |awk '{print $$2}')"

config: ## Generate skywire.json
	-./skywire-cli visor gen-config -o  ./skywire.json -r

clean: ## Clean project: remove created binaries and apps
	-rm -rf ./apps
	-rm -f ./skywire-visor ./skywire-cli ./setup-node ./hypervisor

install: ## Install `skywire-visor`, `skywire-cli`, `hypervisor`, `dmsgpty`
	${OPTS} go install ${BUILD_OPTS} ./cmd/skywire-visor ./cmd/skywire-cli ./cmd/setup-node ./cmd/hypervisor ./cmd/dmsgpty

rerun: stop
	${OPTS} go build -race -o ./skywire-visor ./cmd/skywire-visor
	-./skywire-cli visor gen-config -o  ./skywire.json -r
	perl -pi -e 's/localhost//g' ./skywire.json
	./skywire-visor skywire.json


lint: ## Run linters. Use make install-linters first	
	${OPTS} golangci-lint run -c .golangci.yml ./...
	# The govet version in golangci-lint is out of date and has spurious warnings, run it separately
	${OPTS} go vet -all ./...

vendorcheck:  ## Run vendorcheck
	GO111MODULE=off vendorcheck ./internal/... 
	GO111MODULE=off vendorcheck ./pkg/... 
	GO111MODULE=off vendorcheck ./cmd/apps/... 
	GO111MODULE=off vendorcheck ./cmd/hypervisor/...
	GO111MODULE=off vendorcheck ./cmd/setup-node/... 
	GO111MODULE=off vendorcheck ./cmd/skywire-cli/... 
	GO111MODULE=off vendorcheck ./cmd/skywire-visor/...

test: ## Run tests
	-go clean -testcache &>/dev/null
	${OPTS} go test ${TEST_OPTS} ./internal/...
	${OPTS} go test ${TEST_OPTS} ./pkg/...

test-no-ci: ## Run no_ci tests
	-go clean -testcache
	${OPTS} go test ${TEST_OPTS_NOCI} ./pkg/transport/... -run "TCP|PubKeyTable"

install-linters: ## Install linters
	- VERSION=1.23.1 ./ci_scripts/install-golangci-lint.sh
	# GO111MODULE=off go get -u github.com/FiloSottile/vendorcheck
	# For some reason this install method is not recommended, see https://github.com/golangci/golangci-lint#install
	# However, they suggest `curl ... | bash` which we should not do
	# ${OPTS} go get -u github.com/golangci/golangci-lint/cmd/golangci-lint
	${OPTS} go get -u golang.org/x/tools/cmd/goimports

format: ## Formats the code. Must have goimports installed (use make install-linters).
	${OPTS} goimports -w -local ${PROJECT_BASE} ./pkg
	${OPTS} goimports -w -local ${PROJECT_BASE} ./cmd
	${OPTS} goimports -w -local ${PROJECT_BASE} ./internal

dep: ## Sorts dependencies
	${OPTS} go mod vendor -v

# Apps 
host-apps: ## Build app 
	${OPTS} go build ${BUILD_OPTS} -o ./apps/skychat ./cmd/apps/skychat	
	${OPTS} go build ${BUILD_OPTS} -o ./apps/helloworld ./cmd/apps/helloworld
	${OPTS} go build ${BUILD_OPTS} -o ./apps/skysocks ./cmd/apps/skysocks
	${OPTS} go build ${BUILD_OPTS} -o ./apps/skysocks-client  ./cmd/apps/skysocks-client

# Bin 
bin: ## Build `skywire-visor`, `skywire-cli`, `hypervisor`
	${OPTS} go build ${BUILD_OPTS} -o ./skywire-visor ./cmd/skywire-visor
	${OPTS} go build ${BUILD_OPTS} -o ./skywire-cli  ./cmd/skywire-cli
	${OPTS} go build ${BUILD_OPTS} -o ./setup-node ./cmd/setup-node
	${OPTS} go build ${BUILD_OPTS} -o ./hypervisor ./cmd/hypervisor
	${OPTS} go build ${BUILD_OPTS} -o ./dmsgpty ./cmd/dmsgpty

release: ## Build `skywire-visor`, `skywire-cli`, `hypervisor` and apps without -race flag
	${OPTS} go build ${BUILD_OPTS} -o ./skywire-visor ./cmd/skywire-visor
	${OPTS} go build ${BUILD_OPTS} -o ./skywire-cli  ./cmd/skywire-cli
	${OPTS} go build ${BUILD_OPTS} -o ./setup-node ./cmd/setup-node
	${OPTS} go build ${BUILD_OPTS} -o ./hypervisor ./cmd/hypervisor
	${OPTS} go build ${BUILD_OPTS} -o ./apps/skychat ./cmd/apps/skychat
	${OPTS} go build ${BUILD_OPTS} -o ./apps/helloworld ./cmd/apps/helloworld
	${OPTS} go build ${BUILD_OPTS} -o ./apps/skysocks ./cmd/apps/skysocks
	${OPTS} go build ${BUILD_OPTS} -o ./apps/skysocks-client  ./cmd/apps/skysocks-client

github-release: ## Create a GitHub release
	goreleaser --rm-dist

# Dockerized skywire-visor
docker-image: ## Build docker image `skywire-runner`
	docker image build --tag=skywire-runner --rm  - < skywire-runner.Dockerfile

docker-clean: ## Clean docker system: remove container ${DOCKER_NODE} and network ${DOCKER_NETWORK}
	-docker network rm ${DOCKER_NETWORK} 
	-docker container rm --force ${DOCKER_NODE}

docker-network: ## Create docker network ${DOCKER_NETWORK}
	-docker network create ${DOCKER_NETWORK}

docker-apps: ## Build apps binaries for dockerized skywire-visor. `go build` with  ${DOCKER_OPTS}
	-${DOCKER_OPTS} go build -race -o ./visor/apps/skychat ./cmd/apps/skychat
	-${DOCKER_OPTS} go build -race -o ./visor/apps/helloworld ./cmd/apps/helloworld
	-${DOCKER_OPTS} go build -race -o ./visor/apps/skysocks ./cmd/apps/skysocks
	-${DOCKER_OPTS} go build -race -o ./visor/apps/skysocks-client  ./cmd/apps/skysocks-client

docker-bin: ## Build `skywire-visor`, `skywire-cli`, `hypervisor`. `go build` with  ${DOCKER_OPTS}
	${DOCKER_OPTS} go build -race -o ./visor/skywire-visor ./cmd/skywire-visor

docker-volume: dep docker-apps docker-bin bin  ## Prepare docker volume for dockerized skywire-visor
	-${DOCKER_OPTS} go build  -o ./docker/skywire-services/setup-node ./cmd/setup-node
	-./skywire-cli visor gen-config -o  ./skywire-visor/skywire.json -r
	perl -pi -e 's/localhost//g' ./visor/skywire.json # To make visor accessible from outside with skywire-cli

docker-run: docker-clean docker-image docker-network docker-volume ## Run dockerized skywire-visor ${DOCKER_NODE} in image ${DOCKER_IMAGE} with network ${DOCKER_NETWORK}
	docker run -it -v $(shell pwd)/visor:/sky --network=${DOCKER_NETWORK} \
		--name=${DOCKER_NODE} ${DOCKER_IMAGE} bash -c "cd /sky && ./skywire-visor skywire.json"

docker-setup-node:	## Runs setup-node in detached state in ${DOCKER_NETWORK}
	-docker container rm setup-node -f
	docker run -d --network=${DOCKER_NETWORK}  	\
	 				--name=setup-node	\
	 				--hostname=setup-node	skywire-services \
					  bash -c "./setup-node setup-node.json"

docker-stop: ## Stop running dockerized skywire-visor ${DOCKER_NODE}
	-docker container stop ${DOCKER_NODE}

docker-rerun: docker-stop
	-./skywire-cli gen-config -o ./visor/skywire.json -r
	perl -pi -e 's/localhost//g' ./visor/skywire.json # To make visor accessible from outside with skywire-cli
	${DOCKER_OPTS} go build -race -o ./visor/skywire-visor ./cmd/skywire-visor
	docker container start -i ${DOCKER_NODE}

run-syslog: ## Run syslog-ng in docker. Logs are mounted under /tmp/syslog
	-rm -rf /tmp/syslog
	-mkdir -p /tmp/syslog
	-docker container rm syslog-ng -f
	docker run -d -p 514:514/udp  -v /tmp/syslog:/var/log  --name syslog-ng balabit/syslog-ng:latest 

integration-startup: ## Starts up the required transports between `skywire-visor`s of interactive testing environment
	./integration/startup.sh

integration-teardown: ## Tears down all saved configs and states of integration executables
	./integration/tear-down.sh

integration-run-generic: ## Runs the generic interactive testing environment
	./integration/run-generic-env.sh

integration-run-messaging: ## Runs the messaging interactive testing environment
	./integration/run-messaging-env.sh

integration-run-proxy: ## Runs the proxy interactive testing environment
	./integration/run-proxy-env.sh

mod-comm: ## Comments the 'replace' rule in go.mod
	./ci_scripts/go_mod_replace.sh comment go.mod

mod-uncomm: ## Uncomments the 'replace' rule in go.mod
	./ci_scripts/go_mod_replace.sh uncomment go.mod

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
	
