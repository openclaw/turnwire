package identity

import (
	"path/filepath"
	"testing"
	"time"
)

func TestIdentityPersistsSignsAndCheckpoints(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "identity")
	first, err := LoadOrCreate(dir, "work", true)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreate(dir, "work", false)
	if err != nil {
		t.Fatal(err)
	}
	if first.PublicKey() != second.PublicKey() {
		t.Fatal("identity key did not persist")
	}
	value := struct {
		Text string `json:"text"`
	}{Text: "hello"}
	signature, err := first.Sign(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(first.PublicKey(), value, signature); err != nil {
		t.Fatal(err)
	}
	value.Text = "tampered"
	if err := Verify(first.PublicKey(), value, signature); err == nil {
		t.Fatal("tampered value verified")
	}
	checkpoint, err := first.Checkpoint(7, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.Identity != "work" || checkpoint.Sequence != 7 || checkpoint.Signature == "" {
		t.Fatalf("checkpoint = %#v", checkpoint)
	}
	if err := VerifyCheckpoint(checkpoint); err != nil {
		t.Fatal(err)
	}
	checkpoint.AuditHead = "tampered"
	if err := VerifyCheckpoint(checkpoint); err == nil {
		t.Fatal("tampered checkpoint verified")
	}
}
