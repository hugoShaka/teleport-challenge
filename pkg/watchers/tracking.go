package watchers

import (
	"context"
	"errors"
	"github.com/cilium/ebpf"
	"log"
	"time"
)

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
			break

		default:
			err := w.printConnections()
			if err != nil {
				return err
			}

		}
	}

	return nil
}

func (w *trackingWatcher) printConnections() error {
	var rawConnection []byte
	var err error

	for err = w.trackingMap.LookupAndDelete(nil, &rawConnection); err == nil; err = w.trackingMap.LookupAndDelete(nil, &rawConnection) {
		// TODO: parse rawConnection
		log.Printf("Connection detected: %v", rawConnection)
	}
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		log.Printf("Error reading tcp_connection_tracking_map: %s", err)
		return err
	}
	return nil
}
