FROM golang AS build

ENV BPF_CLANG=clang

RUN apt-get update && \
    apt-get -yq install clang llvm libc6-dev-i386 && \
    rm -rf /var/lib/apt/lists/*

COPY . /src/app

WORKDIR /src/app

RUN go generate ./bpf && \
    go build -o dist/ github.com/hugoshaka/teleport-challenge/cmd/teleport-challenge

FROM gcr.io/distroless/base AS final

COPY --from=build /src/app/dist/teleport-challenge /usr/local/bin/teleport-challenge

CMD "/usr/local/bin/teleport-challenge"