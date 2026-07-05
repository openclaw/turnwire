package mcpserver

import (
	"sync"
	"time"
)

type windowBudget struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	used   []time.Time
}

func newWindowBudget(limit int, window time.Duration) *windowBudget {
	return &windowBudget{limit: limit, window: window, used: make([]time.Time, 0, limit)}
}

func (b *windowBudget) Take(now time.Time) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	cutoff := now.Add(-b.window)
	first := 0
	for first < len(b.used) && !b.used[first].After(cutoff) {
		first++
	}
	if first > 0 {
		copy(b.used, b.used[first:])
		b.used = b.used[:len(b.used)-first]
	}
	if len(b.used) > 0 && now.Before(b.used[len(b.used)-1]) {
		b.used = b.used[:0]
	}
	if len(b.used) >= b.limit {
		return false, nil
	}
	b.used = append(b.used, now)
	return true, nil
}
