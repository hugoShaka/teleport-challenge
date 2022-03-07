package watchers

import (
	"context"
	"github.com/cilium/ebpf"
	"inet.af/netaddr"
	"log"
	"time"
)

type blockingWatcher struct {
	blockingMap *ebpf.Map
	metricMap   *ebpf.Map
	period      time.Duration
	threshold   int
}

func NewBlockingWatcher(metricMap, blockingMap *ebpf.Map, period time.Duration, threshold int) Watcher {
	return &blockingWatcher{
		blockingMap: blockingMap,
		metricMap:   metricMap,
		period:      period,
		threshold:   threshold,
	}
}

func (w *blockingWatcher) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.period)

	for range ticker.C {
		select {
		case <-ctx.Done():
			log.Println("Stopping blocking watcher")
			return nil

		default:
			err := w.searchInfringingIPs(ctx)
			if err != nil {
				return err
			}

		}
	}

	return nil
}

func (w *blockingWatcher) searchInfringingIPs(ctx context.Context) error {
	var key [4]byte
	var value [][]byte
	var ip netaddr.IP
	// Checking IP metrics to decide IP block
	values := w.metricMap.Iterate()
	for values.Next(&key, &value) {
		ip = netaddr.IPFrom4(key)
		// metric, _ := unmarshalIPMetric(value)
		log.Printf("ip: %v, value: %v", ip.String(), metric)
	}

	err := values.Err()
	if err != nil {
		log.Printf("Error reading ip_metic_map: %s", err)
		return err
	}
	return nil
}
