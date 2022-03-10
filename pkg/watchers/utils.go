package watchers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"inet.af/netaddr"
)

type ipMetric struct {
	synReceived uint64
	ports       map[uint16]bool // this map acts as a set
}

// unmarshalIPMetric converts an eBPF ip_metric into an ipMetric go struct.
func unmarshalIPMetric(data []byte) (*ipMetric, error) {
	if (len(data) < 10) || (len(data)%2 == 1) {
		return nil, errors.New("failed to parse ip_metric: invalid size")
	}

	// Danger: Endianness is tricky and varies from the information source.
	// synReceived is computed locally thus it follows host endianness, usually little-endian. Uvarint will work anyway.
	synReceived, _ := binary.Uvarint(data[:8])
	numPorts := (len(data) - 8) / 2

	ports := make(map[uint16]bool)

	for i := 0; i < numPorts; i++ {
		// ports are bytes copied directly from "the wire", thus they follow network endianess, which is big-endian
		port := binary.BigEndian.Uint16(data[8+2*i : 10+2*i])
		if port != 0 {
			ports[port] = true
		}
	}

	result := ipMetric{
		synReceived: synReceived,
		ports:       ports,
	}

	return &result, nil
}

// mergeIPMetric merge ipMetric coming from different CPUs into a single one
func mergeIPMetric(metrics []*ipMetric) *ipMetric {
	result := ipMetric{
		synReceived: 0,
		ports:       make(map[uint16]bool),
	}
	for _, cpuMetric := range metrics {
		result.synReceived += cpuMetric.synReceived
		for port := range cpuMetric.ports {
			result.ports[port] = true
		}
	}

	return &result
}
