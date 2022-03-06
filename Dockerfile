FROM golang AS build

ENV BPF_CLANG=clang

RUN apt-get update && \
    apt-get -yq install clang llvm libc6-dev-i386 && \
    rm -rf /var/lib/apt/lists/*

COPY . /src/app

WORKDIR /src/app

RUN go generate ./bpf && \
    go build -o dist/ github.com/hugoshaka/teleport-challenge/bpf

# Should be switched to a gcr.io/distroless image for prod purposes, but for now I need the ability to pop a shell
FROM debian:stable-slim AS final

# RUN useradd -Ms /usr/sbin/nologin user && echo "user hard memlock -1"
COPY --from=build /src/app/dist/bpf /usr/local/bin/teleport-challenge

# USER user
CMD "/usr/local/bin/teleport-challenge"