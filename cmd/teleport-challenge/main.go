package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/docopt/docopt-go"
	"github.com/hugoshaka/teleport-challenge/bpf"
	"github.com/hugoshaka/teleport-challenge/pkg/watchers"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/errgroup"
)

const (
	metricsPort = 8080
)

var (
	monitoringEndpoint  = fmt.Sprintf(":%d", metricsPort)
	metricServerTimeout = 5 * time.Second
)

func main() {
	usage := `Teleport challenge.
Leverages eBPF to log all incoming IPv4 TCP connections and block scanning IPs from contacting the server.

Usage:
  teleport-challenge [--interface=<if>] [--tracking-period=<tp>] [--detect-scan-period=<dp>] [--threshold=<n>]
  teleport-challenge -h | --help
  teleport-challenge --version

Options:
  -h --help                     Show this screen.
  --version                     Show version.
  -i --interface=<if>           Interface to watch [default: lo].
  -t --tracking-period=<tp>     Poll interval to read new connections [default: 1s].
  -d --detect-scan-period=<dp>  Poll interval to detect port scans [default: 1m].
  -n --threshold=<n>            IPs connecting to more ports than <n> in the last <dp> will be banned [default: 3].`

	// Initialize context and parse arguments
	ctx, cancel := makeContext()
	defer cancel()

	arguments, _ := docopt.ParseDoc(usage)

	rawTrackingPeriod, _ := arguments.String("--tracking-period")
	trackingPeriod, _ := time.ParseDuration(rawTrackingPeriod)
	rawBlockingPeriod, _ := arguments.String("--detect-scan-period")
	blockingPeriod, _ := time.ParseDuration(rawBlockingPeriod)
	blockThreshold, _ := arguments.Int("--threshold")
	interfaceName, _ := arguments.String("--interface")

	iface, err := findInterface(interfaceName)

	if err != nil {
		log.Fatalf("Error recovering interface: %v", err)
	}

	// Load BPF objects
	trackingMap, metricMap, blockingMap := bpf.LoadAndAttach(iface)

	// Initialize the watchers
	trackingWatcher := watchers.NewTrackingWatcher(trackingMap, trackingPeriod)
	blockingWatcher := watchers.NewBlockingWatcher(metricMap, blockingMap, blockingPeriod, blockThreshold)

	// Run everything
	workGroup, ctx := errgroup.WithContext(ctx)
	workGroup.Go(func() error { return trackingWatcher.Run(ctx) })
	workGroup.Go(func() error { return blockingWatcher.Run(ctx) })

	// Setup monitoring server
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	server := &http.Server{
		Addr:              monitoringEndpoint,
		Handler:           mux,
		IdleTimeout:       metricServerTimeout,
		ReadTimeout:       metricServerTimeout,
		WriteTimeout:      metricServerTimeout,
		ReadHeaderTimeout: metricServerTimeout,
	}
	workGroup.Go(func() error { return server.ListenAndServe() })
	// To have a graceful shutdown we register a coroutine waiting for context cancellation and stopping the server
	go func() {
		if <-ctx.Done(); true {
			stopCtx, cancel := context.WithTimeout(context.Background(), metricServerTimeout)
			defer cancel()
			log.Println("Stopping monitoring server")
			_ = server.Shutdown(stopCtx)
		}
	}()

	// Wait for an error or context cancellation
	exitCode := 0
	if err := workGroup.Wait(); err != nil {
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, http.ErrServerClosed):
			log.Println("Shutting down")
		default:
			log.Printf("Unhandled error received: %v", err)
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

func findInterface(name string) (int, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0, err
	}
	for _, iface := range ifaces {
		if iface.Name == name {
			return iface.Index, nil
		}
	}
	return 0, errors.New("interface not found")
}
