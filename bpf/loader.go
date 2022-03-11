package bpf

import (
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Note: include is hardcoded to x86_64, this could be changed via Makefile to support arm64
// a better way could be to vendor linux headers and provide an arch-independent mapping like
// https://github.com/cilium/cilium/commit/8b3435f91af72dfbc2eef13f463b95ec08faec55
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf xdp.c -- -I/usr/include/x86_64-linux-gnu

// LoadAndAttach loads the eBPF XDP program with it maps and attaches them to the given interface.
func LoadAndAttach(iface int) (*ebpf.Map, *ebpf.Map, *ebpf.Map) {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Error loading BPF objects: %v", err)
	}

	log.Println("BPF objects loaded")

	if _, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgMain,
		Interface: iface,
		Flags:     0,
	}); err != nil {
		log.Fatalf("Error attaching XDP program: %v", err)
	}

	log.Println("XDP program attached")

	return objs.TcpConnectionTrackingMap, objs.IpMetricMap, objs.IpBlockedMap
}
