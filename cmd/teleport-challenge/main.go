package main

import (
	"context"
	"fmt"
	"github.com/docopt/docopt-go"
	"github.com/hugoshaka/teleport-challenge/bpf"
	"github.com/hugoshaka/teleport-challenge/pkg/watchers"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/errgroup"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"
)

const (
	appName     = "teleport-challenge"
	metricsPort = 8080
)

var (
	monitoringEndpoint = fmt.Sprintf(":%d", metricsPort)
)

func main() {
	usage := `Teleport challenge.
Leverages eBPF to log all incoming IPv4 TCP connections and block scanning IPs from contacting the server.

Usage:
  teleport-challenge [--interface=<if>]
  teleport-challenge -h | --help
  teleport-challenge --version

Options:
  -h --help                  Show this screen.
  --version                  Show version.
  -i --interface=<if>        Interface to watch [default: "lo"].`

	// Initialize context and parse arguments
	ctx, cancel := makeContext()
	defer cancel()

	arguments, _ := docopt.ParseDoc(usage)
	fmt.Println(arguments)
	// TODO: get values from argv
	trackingPeriod, _ := time.ParseDuration("1s")
	blockingPeriod, _ := time.ParseDuration("1m")
	blockThreshold := 3
	iface := 1

	// Load BPF objects
	trackingMap, metricMap, blockingMap := bpf.LoadAndAttach(iface)

	// Initialize the watchers
	trackingWatcher := watchers.NewTrackingWatcher(trackingMap, trackingPeriod)
	blockingWatcher := watchers.NewBlockingWatcher(metricMap, blockingMap, blockingPeriod, blockThreshold)

	// Run everything
	workGroup, ctx := errgroup.WithContext(ctx)
	workGroup.Go(func() error { return trackingWatcher.Run(ctx) })
	workGroup.Go(func() error { return blockingWatcher.Run(ctx) })

	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(monitoringEndpoint, nil)

	// Wait for an error or context cancellation
	exitCode := 0

	if err := workGroup.Wait(); err != nil {
		switch err {
		case context.Canceled:
			log.Println("Shutting down")
		default:
			log.Println("Unhandled error received: %v", err)
			exitCode = 1
		}
	}
	os.Exit(exitCode)
}

// makeContext creates a context, traps Interrupts and cancels the context if needed.
func makeContext() (context.Context, func()) {
	ctx := context.Background()

	ctx, cancel := context.WithCancel(ctx)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		select {
		case <-c:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, func() {
		signal.Stop(c)
		cancel()
	}
}
