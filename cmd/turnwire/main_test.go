package main

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestSignalCancellationRestoresHandlingBeforeCancel(t *testing.T) {
	signals := make(chan os.Signal, 1)
	var restoreCalls atomic.Int32
	ctx, stop := signalCancellationContext(context.Background(), signals, func() {
		restoreCalls.Add(1)
	})
	t.Cleanup(stop)

	signals <- os.Interrupt
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("first signal did not cancel the context")
	}
	if calls := restoreCalls.Load(); calls != 1 {
		t.Fatalf("restore calls at cancellation = %d, want 1", calls)
	}
	stop()
	if calls := restoreCalls.Load(); calls != 1 {
		t.Fatalf("restore calls after repeated stop = %d, want 1", calls)
	}
}
