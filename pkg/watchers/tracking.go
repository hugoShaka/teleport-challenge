package watchers

import (
	"context"
	"errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"log"
	"time"

	"github.com/cilium/ebpf"
)

var (
	connectionsReceived = promauto.NewCounter(prometheus.CounterOpts{
		Name: "teleportchallenge_connections_received_total",
		Help: "The amount of TCP connections received since the start of the application.",
	})
)

// trackingWatcher reads the BPF trackingMap and logs all incoming connections.
type trackingWatcher struct {
	period      time.Duration
	trackingMap *ebpf.Map
}

func NewTrackingWatcher(trackingMap *ebpf.Map, period time.Duration) Watcher {
	return &trackingWatcher{
		period:      period,
		trackingMap: trackingMap,
	}
}

// Run executes printConnections at every tick until the context is cancelled, or if we face an error.
func (w *trackingWatcher) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.period)

	for range ticker.C {
		select {
		case <-ctx.Done():
			log.Println("Stopping tracking watcher")
			return nil

		default:
			err := w.printConnections()
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// printConnections reads all connections from the trackingMap and logs them
func (w *trackingWatcher) printConnections() error {
	var rawConnection [12]byte
	var err error

	for err = w.trackingMap.LookupAndDelete(nil, &rawConnection); err == nil; err = w.trackingMap.LookupAndDelete(nil, &rawConnection) {
		connection := unmarshallTCPConnection(rawConnection)
		log.Printf("New connection: %s", connection)
		connectionsReceived.Inc()
	}
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		log.Printf("Error reading tcp_connection_tracking_map: %s", err)
		return err
	}
	return nil
}
