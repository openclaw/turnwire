package identity

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	checkpoint, err := first.Checkpoint(7, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", time.Unix(1, 0))
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

func TestRotationProvesContinuityAndRevocationDeletesKey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "identity")
	original, err := LoadOrCreate(dir, "work", true)
	if err != nil {
		t.Fatal(err)
	}
	rotationPlan, err := PrepareRotation(dir, "work", time.Unix(2, 0))
	if err != nil {
		t.Fatal(err)
	}
	rotation := rotationPlan.Certificate()
	if err := VerifyRotation(rotation, "work", original.PublicKey()); err != nil {
		t.Fatal(err)
	}
	beforeCommit, err := LoadOrCreate(dir, "work", false)
	if err != nil || beforeCommit.PublicKey() != original.PublicKey() {
		t.Fatal("preparing rotation changed the identity")
	}
	if err := rotationPlan.Commit(); err != nil {
		t.Fatal(err)
	}
	rotated, err := LoadOrCreate(dir, "work", false)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.PublicKey() != rotation.NewPublicKey || rotated.PublicKey() == original.PublicKey() {
		t.Fatal("rotation did not replace the local identity key")
	}
	tampered := rotation
	tampered.NewPublicKey = original.PublicKey()
	if err := VerifyRotation(tampered, "work", original.PublicKey()); err == nil {
		t.Fatal("tampered rotation verified")
	}
	revocationPlan, err := PrepareRevocation(dir, "work", time.Unix(3, 0))
	if err != nil {
		t.Fatal(err)
	}
	revocation := revocationPlan.Certificate()
	if stillPresent, err := LoadOrCreate(dir, "work", false); err != nil || stillPresent.PublicKey() != rotated.PublicKey() {
		t.Fatal("preparing revocation deleted the identity")
	}
	if err := revocationPlan.Commit(); err != nil {
		t.Fatal(err)
	}
	if revocation.PublicKey != rotated.PublicKey() || revocation.Signature == "" {
		t.Fatalf("revocation = %#v", revocation)
	}
	if _, err := LoadOrCreate(dir, "work", false); !errors.Is(err, os.ErrNotExist) && (err == nil || !strings.Contains(err.Error(), "no such file")) {
		t.Fatalf("load revoked identity error = %v", err)
	}
}
