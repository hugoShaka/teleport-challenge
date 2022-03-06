FROM golang

RUN apt-get update && apt-get -yq install clang llvm libc6-dev-i386