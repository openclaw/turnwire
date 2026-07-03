package approval

import (
	"testing"
	"time"
)

func TestApprovalBindsExactMessageHash(t *testing.T) {
	store, err := Open(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	pending := Pending{MessageID: "message-1", Direction: "outbound", Source: "work", Destination: "personal", Body: "hello", BodySHA256: "abc", ReasonCode: "ambiguous", CreatedAt: "2026-01-01T00:00:00Z"}
	if err := store.SavePending(pending); err != nil {
		t.Fatal(err)
	}
	retry := pending
	retry.ReasonCode = "different_explanation"
	retry.CreatedAt = "2026-01-02T00:00:00Z"
	if err := store.SavePending(retry); err != nil {
		t.Fatalf("security-equivalent pending retry: %v", err)
	}
	conflict := pending
	conflict.Direction = "inbound"
	if err := store.SavePending(conflict); err == nil {
		t.Fatal("cross-direction pending replay was accepted")
	}
	loaded, err := store.Pending(pending.MessageID)
	if err != nil || loaded.Body != pending.Body {
		t.Fatalf("Pending = %#v, %v", loaded, err)
	}
	binding := pending.Binding()
	if ok, err := store.IsApproved(binding); err != nil || ok {
		t.Fatalf("premature approval = %v, %v", ok, err)
	}
	if err := store.Approve(binding, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if ok, err := store.IsApproved(binding); err != nil || !ok {
		t.Fatalf("approval = %v, %v", ok, err)
	}
	mismatched := binding
	mismatched.BodySHA256 = "different"
	if ok, err := store.IsApproved(mismatched); err != nil || ok {
		t.Fatalf("mismatched approval = %v, %v", ok, err)
	}
	mismatched = binding
	mismatched.Direction = "inbound"
	if ok, err := store.IsApproved(mismatched); err != nil || ok {
		t.Fatalf("cross-direction approval = %v, %v", ok, err)
	}
	if err := store.Approve(binding, time.Unix(2, 0)); err != nil {
		t.Fatalf("idempotent approval: %v", err)
	}
}
