package budget

import (
	"path/filepath"
	"testing"
	"time"
)

func TestCounterPersistsAcrossRestartAndClockRollback(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	now := time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)
	first, err := Open(dir, "guard", 2, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := first.Take(now)
	if err != nil || !allowed {
		t.Fatalf("first take = %v, %v", allowed, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Open(dir, "guard", 2, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	allowed, err = second.Take(now.Add(-time.Minute))
	if err != nil || !allowed {
		t.Fatalf("rollback take = %v, %v", allowed, err)
	}
	allowed, err = second.Take(now)
	if err != nil || allowed {
		t.Fatalf("exhausted take = %v, %v", allowed, err)
	}
	allowed, err = second.Take(now.Add(time.Hour))
	if err != nil || !allowed {
		t.Fatalf("new-window take = %v, %v", allowed, err)
	}
}
