package watchers

import (
	"context"
	"github.com/cilium/ebpf"
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
	return nil
}
