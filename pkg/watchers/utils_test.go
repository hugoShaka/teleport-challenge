package watchers

import (
	"github.com/stretchr/testify/assert"
	"inet.af/netaddr"
	"testing"
)

func TestUnmarshallIPMetric(t *testing.T) {
	testCases := []struct {
		name     string
		data     []byte
		expected *ipMetric
	}{
		{
			"SingleCall1Port",
			[]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 80},
			&ipMetric{
				synReceived: 1,
				ports:       map[uint16]bool{80: true},
			},
		},
		{
			"DoubleCall10Port",
			[]byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 82, 0, 81, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			&ipMetric{
				synReceived: 2,
				ports:       map[uint16]bool{81: true, 82: true},
			},
		},
		{
			"4Calls3PortsWithEmpty",
			[]byte{4, 0, 0, 0, 0, 0, 0, 0, 31, 150, 31, 146, 0, 0, 31, 144},
			&ipMetric{
				synReceived: 4,
				ports:       map[uint16]bool{8086: true, 8082: true, 8080: true},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, _ := unmarshalIPMetric(tc.data)

			assert.Equal(t, tc.expected, result)
		})

	}
}

func TestMergeIPMetric(t *testing.T) {
	testCases := []struct {
		name     string
		input    []*ipMetric
		expected *ipMetric
	}{
		{
			"NotInitializedIPMetric",
			[]*ipMetric{},
			&ipMetric{
				0,
				map[uint16]bool{},
			},
		},
		{
			"SingleIPMetric",
			[]*ipMetric{
				{
					65,
					map[uint16]bool{
						80: true, 8080: true,
					},
				},
			},
			&ipMetric{
				65,
				map[uint16]bool{
					80: true, 8080: true,
				},
			},
		},
		{
			"TwoIdenticalIPMetric",
			[]*ipMetric{
				{
					65,
					map[uint16]bool{
						80: true, 8080: true,
					},
				},
				{
					65,
					map[uint16]bool{
						80: true, 8080: true,
					},
				},
			},
			&ipMetric{
				130,
				map[uint16]bool{
					80: true, 8080: true,
				},
			},
		},
		{
			"TwoDifferentIPMetric",
			[]*ipMetric{
				{
					65,
					map[uint16]bool{
						80: true, 8080: true,
					},
				},
				{
					65,
					map[uint16]bool{
						443: true, 8443: true,
					},
				},
			},
			&ipMetric{
				130,
				map[uint16]bool{
					80: true, 443: true, 8080: true, 8443: true,
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := mergeIPMetric(tc.input)

			assert.Equal(t, tc.expected, result)
		})

	}
}
