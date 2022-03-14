export BPF_CLANG ?= clang

DOCKER_BIN ?= docker
CAPABILITIES ?= --capp-add SYS_ADMIN

.PHONY: docker nerdctl test end2end bpf build all

all: bpf build docker

build: dist/teleport-challenge

bpf: bpf/bpf_bpfeb.go bpf/bpf_bpfeb.o bpf/bpf_bpfel.go bpf/bpf_bpfel.o

docker:
	$(DOCKER_BIN) build . -t hugoshaka/teleport-challenge:local

docker-run: docker
	$(DOCKER_BIN) run -it --read-only $(CAPABILITIES) --ulimit memlock=-1:-1 --network host hugoshaka/teleport-challenge:local teleport-challenge

nerdctl: DOCKER_BIN=nerdctl
nerdctl: docker

nerdctl-run: DOCKER_BIN=nerdctl
nerdctl-run: CAPABILITIES=--cap-add BPF --cap-add NET_ADMIN --cap-add CAP_PERFMON
nerdctl-run: docker-run

test:
	go test -v github.com/hugoshaka/teleport-challenge/pkg/watchers

end2end:
	docker-compose up --build

lint:
	golangci-lint run -v

bpf/bpf_%.go bpf/bpf_%.o: bpf/xdp.c bpf/types.h bpf/loader.go bpf/headers/
	go generate ./bpf

dist/teleport-challenge: $(shell find . -type f -iname *.go)
	go build -o dist/ github.com/hugoshaka/teleport-challenge/cmd/teleport-challenge
