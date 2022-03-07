package watchers

import (
	"encoding/binary"
	"errors"
)

type ipMetric struct {
	synReceived uint64
	ports       []uint16
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

	ports := make([]uint16, 0, numPorts)

	for i := 0; i < numPorts; i++ {
		// ports are bytes copied directly from "the wire", thus they follow network endianess, which is big-endian
		port := binary.BigEndian.Uint16(data[8+2*i : 10+2*i])
		if port != 0 {
			ports = append(ports, port)
		}
	}

	result := ipMetric{
		synReceived: synReceived,
		ports:       ports,
	}

	return &result, nil
}
