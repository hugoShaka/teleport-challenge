package watchers

import (
	"context"
	"log"
	"time"

	"github.com/cilium/ebpf"
	"inet.af/netaddr"
)

// blockingWatcher reads the BPF metricMap and blocks IPs doing port scan via the blockingMap.
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

	// I'm not happy with this as we have to wait for the next tick to exit, this slows down considerably the shutdown
	for range ticker.C {
		select {
		case <-ctx.Done():
			log.Println("Stopping blocking watcher")

			return nil

		default:
			err := w.searchInfringingIPs()
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// searchInfringingIPs consumes entirely the metricMap searching for source IPs that connected to too many
// ports since the last tick. Infringing IPs are then added to the block list.
func (w *blockingWatcher) searchInfringingIPs() error {
	var key [4]byte
	var value [][]byte
	var ip netaddr.IP

	// Iterate over every IP
	values := w.metricMap.Iterate()
	for values.Next(&key, &value) {
		err := w.metricMap.Delete(key)
		if err != nil {
			return err
		}
		ip = netaddr.IPFrom4(key)
		metrics := make([]*ipMetric, 0, len(value))

		// Iterate over every CPU
		for _, cpuValue := range value {
			cpuMetric, _ := unmarshalIPMetric(cpuValue)
			metrics = append(metrics, cpuMetric)
		}

		// Consolidate metrics from all CPUs into a single struct
		metric := mergeIPMetric(metrics)
		if len(metric.ports) > w.threshold {
			err := w.blockIP(ip, metric)
			if err != nil {
				return err
			}
		}
	}

	if err := values.Err(); err != nil {
		log.Printf("Error reading ip_metic_map: %s", err)
		return err
	}
	return nil
}

// blockIP adds an IP to the blocking map.
func (w *blockingWatcher) blockIP(ip netaddr.IP, metric *ipMetric) error {
	ports := make([]uint16, len(metric.ports))

	// Create a slice with all the ports
	i := 0
	for k := range metric.ports {
		ports[i] = k
		i++
	}

	log.Printf("Port scan detected: %v on ports %v", ip, ports)

	key := ip.As4()
	blockTime := uint64(time.Now().Unix())

	err := w.blockingMap.Put(key, blockTime)
	if err != nil {
		log.Printf("Error blocking an IP: %v", err)
		return err
	}
	return nil
}
