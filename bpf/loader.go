package main

import (
	"encoding/binary"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"inet.af/netaddr"
	"log"
	"time"
)

// Note: include is hardcoded to x86_64, this could be changed via Makefile to support arm64
// a better way could be to vendor linux headers and provide an arch-independent mapping like
// https://github.com/cilium/cilium/commit/8b3435f91af72dfbc2eef13f463b95ec08faec55
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS bpf metrics.c -- -I/usr/include/x86_64-linux-gnu

// TODO: This is a proof-of-concept, this should be broken into smaller packages at some point
func main() {

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Error loading BPF objects: %v", err)
	}
	defer objs.Close()

	log.Println("BPF objects loaded")

	if _, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgMain,
		Interface: 1, // TODO: discover the right interface instead of attaching to loopback
		Flags:     0,
	}); err != nil {
		log.Fatalf("Error attaching XDP program: %v", err)
	}

	log.Println("XDP program attached")

	// Test blocklist
	var localhostKey uint32 = 16777343
	var localhostValue uint64 = 0
	err := objs.IpBlockedMap.Put(localhostKey, localhostValue)
	if err != nil {
		log.Fatalf("Error adding localhost to the blocked ips list: %v", err)
	}

	// TODO: clean this
	var key uint32
	keyb := make([]byte, 4)
	var keyb4 [4]byte
	var value [][]byte
	var ip netaddr.IP

	ticker := time.NewTicker(1 * time.Second)

	for range ticker.C {
		values := objs.IpMetricMap.Iterate()
		for values.Next(&key, &value) {
			binary.LittleEndian.PutUint32(keyb, key)
			for i := 0; i < 4; i++ {
				keyb4[i] = keyb[i]
			}
			ip = netaddr.IPFrom4(keyb4)
			log.Printf("ip: %v, value: %v, key: %v", ip.String(), value, key)
		}

		err := values.Err()
		if err != nil {
			log.Printf("Error: %s", err)
		}

		log.Printf("\n")
	}
}
