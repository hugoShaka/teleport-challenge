export BPF_CLANG ?= clang

.PHONY: docker test end2end bpf build all

all: bpf build docker

build: dist/teleport-challenge

bpf: bpf/bpf_bpfeb.go bpf/bpf_bpfeb.o bpf/bpf_bpfel.go bpf/bpf_bpfel.o

docker:
	docker build . -t hugoshaka/teleport-challenge:local

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
