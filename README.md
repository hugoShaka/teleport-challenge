# Teleport challenge

This program outputs all incoming TCP connections, detects port scans and block the infringing IPs.

## Design and technical considerations

It works by leveraging BPF programs to:
* detect all incoming connections (SYN packets)
* keep track of which IP has connected to which port
* reject traffic coming from specific blocked IPs

The golang program's job is to:
* load the BPF programs and attach them
* regularly fetch connection data from the BPF program and output connections to stdout
* flush the history of "who spoke to which port" on a regular basis
* take action when an IP has connected to too many ports (add the ip to the BPF program's blocklist)

Communication between BPF and userspace is done through BPF maps, see `./bpf/types.h` for more information.

To do so it relies on two "watchers":
* each watcher is woken up every X seconds/minute and reads its BPF map
* the tracking watcher is logging the connections (by default every second)
* the blocking watcher is detecting port scans and issuing blocks (by default every minute)

### Limitations

The program might not detect connections if the amount of incoming connections
between two timer ticks exceeds the map size. The program might not detect IP
scans if the amount of connecting IPs exceeds the map size.

This program requires a Linux kernel newer than 4.20.

### Security considerations

The docker container has to run with `CAP_SYS_ADMIN` to be allowed to load and attach BPF programs.
This capability is overpowered and a saner one has been introduced since Linux 5.8: `CAP_BPF`.

The executable must be run as `root` as the BPF type is `BPF_PROG_TYPE_XDP` (this type allows manipulating packets
as early as possible, before skb creation).

## Building

### Requirements

For building locally:

```
go 1.17
clang
llvm
llvm-strip
libc6-dev-i386
make
```

For building the container itself:
```shell
docker
```

For tests and lint:
```shell
docker-compose
golangci-lint
```

### Steps

Build the bpf by running
```shell
$ export BPF_CLANG=clang  # this can be clang-11/12/13/.. depending on your setup
$ make bpf

Compiled /home/shaka/perso/teleport-challenge/bpf/bpf_bpfel.o
Stripped /home/shaka/perso/teleport-challenge/bpf/bpf_bpfel.o
Wrote /home/shaka/perso/teleport-challenge/bpf/bpf_bpfel.go
Compiled /home/shaka/perso/teleport-challenge/bpf/bpf_bpfeb.o
Stripped /home/shaka/perso/teleport-challenge/bpf/bpf_bpfeb.o
Wrote /home/shaka/perso/teleport-challenge/bpf/bpf_bpfeb.go
```

Build the go binary by running
```shell
make build
```

Build the docker container (this is a self-sufficient command, it will rebuild both bpf and golang)
```shell
make docker
```

## Running

With docker

```shell
# For all kernels
docker run -it --cap-add SYS_ADMIN --ulimit memlock=-1:-1 --network host hugoshaka/teleport-challenge:local
# For linux >= 5.8
docker run -it --cap-add BPF --ulimit memlock=-1:-1 --network host hugoshaka/teleport-challenge:local
```

Without docker as root

```shell
ulimit -l unlimited
./dist/teleport-challenge
```
