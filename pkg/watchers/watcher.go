package watchers

import "context"

// Watcher is a generic interface for something that will run and watch for BPF map content on a regular basis
type Watcher interface {
	Run(ctx context.Context) error
}
