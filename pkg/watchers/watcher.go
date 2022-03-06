package watchers

import "context"

type Watcher interface {
	Run(ctx context.Context) error
}
