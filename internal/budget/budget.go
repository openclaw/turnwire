// Package budget provides durable fail-closed fixed-window accounting.
package budget

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/openclaw/turnwire/internal/securestore"
)

type state struct {
	WindowStartedAt string `json:"window_started_at"`
	Used            int    `json:"used"`
}

// Counter persists every admitted operation before returning success. A
// corrupt or unwritable counter fails closed instead of granting a fresh
// process-local allowance.
type Counter struct {
	mu     sync.Mutex
	store  *securestore.Store
	name   string
	limit  int
	window time.Duration
	state  state
}

// Open loads a durable counter from an owner-only state directory.
func Open(dir, name string, limit int, window time.Duration) (*Counter, error) {
	if name == "" || limit <= 0 || window <= 0 {
		return nil, errors.New("budget name, limit, and window are required")
	}
	store, err := securestore.Open(dir, true, "budget directory")
	if err != nil {
		return nil, err
	}
	counter := &Counter{store: store, name: "budget-" + name + ".json", limit: limit, window: window}
	encoded, err := store.Read(counter.name)
	if errors.Is(err, os.ErrNotExist) {
		return counter, nil
	}
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("load %s budget: %w", name, err)
	}
	if err := json.Unmarshal(encoded, &counter.state); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("decode %s budget: %w", name, err)
	}
	if counter.state.Used < 0 || counter.state.WindowStartedAt == "" {
		_ = store.Close()
		return nil, fmt.Errorf("decode %s budget: invalid state", name)
	}
	if _, err := time.Parse(time.RFC3339Nano, counter.state.WindowStartedAt); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("decode %s budget timestamp: %w", name, err)
	}
	return counter, nil
}

// Take durably charges one operation. Clock rollback preserves the existing
// window until wall time catches up, preventing restart or time manipulation
// from replenishing the allowance.
func (c *Counter) Take(now time.Time) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.store == nil {
		return false, errors.New("budget is closed")
	}
	now = now.UTC()
	if c.state.WindowStartedAt == "" {
		c.state.WindowStartedAt = now.Format(time.RFC3339Nano)
	}
	started, err := time.Parse(time.RFC3339Nano, c.state.WindowStartedAt)
	if err != nil {
		return false, err
	}
	if !now.Before(started) && now.Sub(started) >= c.window {
		c.state = state{WindowStartedAt: now.Format(time.RFC3339Nano)}
	}
	if c.state.Used >= c.limit {
		return false, nil
	}
	next := c.state
	next.Used++
	encoded, err := json.Marshal(next)
	if err != nil {
		return false, err
	}
	if err := c.store.Replace(c.name, encoded); err != nil {
		return false, fmt.Errorf("persist budget: %w", err)
	}
	c.state = next
	return true, nil
}

// Close releases the held state-directory descriptor.
func (c *Counter) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.store == nil {
		return nil
	}
	err := c.store.Close()
	c.store = nil
	return err
}
