package mailbox

import (
	"testing"
	"time"
)

func TestWindowBudgetExpiresAndHandlesClockRollback(t *testing.T) {
	budget := newWindowBudget(1, time.Minute)
	now := time.Unix(1000, 0)
	first, err := budget.Take(now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := budget.Take(now)
	if err != nil {
		t.Fatal(err)
	}
	if !first || second {
		t.Fatal("budget did not enforce its limit")
	}
	allowed, err := budget.Take(now.Add(time.Minute))
	if err != nil || !allowed {
		t.Fatal("budget did not expire its window")
	}
	allowed, err = budget.Take(now.Add(-time.Minute))
	if err != nil || !allowed {
		t.Fatal("budget did not reset after clock rollback")
	}
}
