package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/openclaw/turnwire/internal/cli"
)

func main() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	ctx, stop := signalCancellationContext(context.Background(), signals, func() {
		signal.Stop(signals)
	})
	code := cli.Run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// signalCancellationContext turns the first signal into graceful cancellation.
// Signal handling is restored before cancellation becomes visible, so a second
// SIGINT or SIGTERM uses the operating system's default termination behavior.
func signalCancellationContext(parent context.Context, signals <-chan os.Signal, restore func()) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	var once sync.Once
	stop := func() {
		once.Do(func() {
			restore()
			cancel()
		})
	}
	go func() {
		select {
		case <-signals:
			stop()
		case <-ctx.Done():
			stop()
		}
	}()
	return ctx, stop
}
