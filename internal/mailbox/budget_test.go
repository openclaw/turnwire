package mailbox

import (
	"testing"
	"time"
)

func TestWindowBudgetExpiresAndHandlesClockRollback(t *testing.T) {
	budget := newWindowBudget(1, time.Minute)
	now := time.Unix(1000, 0)
	if !budget.take(now) || budget.take(now) {
		t.Fatal("budget did not enforce its limit")
	}
	if !budget.take(now.Add(time.Minute)) {
		t.Fatal("budget did not expire its window")
	}
	if !budget.take(now.Add(-time.Minute)) {
		t.Fatal("budget did not reset after clock rollback")
	}
}
