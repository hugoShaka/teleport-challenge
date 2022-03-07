package watchers

import (
	"github.com/stretchr/testify/assert"
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
				ports:       []uint16{80},
			},
		},
		{
			"DoubleCall10Port",
			[]byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 82, 0, 81, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			&ipMetric{
				synReceived: 2,
				ports:       []uint16{82, 81},
			},
		},
		{
			"4Calls3PortsWithEmpty",
			[]byte{4, 0, 0, 0, 0, 0, 0, 0, 31, 150, 31, 146, 0, 0, 31, 144},
			&ipMetric{
				synReceived: 4,
				ports:       []uint16{8086, 8082, 8080},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// ----- call -----------------------------------------------------
			result, _ := unmarshalIPMetric(tc.data)

			// ----- verify ---------------------------------------------------
			assert.Equal(t, tc.expected, result)
		})

	}
}
