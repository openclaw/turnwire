package approval

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSavePendingSpillsBodyThatExceedsStoreAfterEscaping(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	body := strings.Repeat("<>", 200_000)
	pending := Pending{
		MessageID: "message-1", Direction: "outbound", Source: "work", Destination: "personal",
		Body: body, BodySHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(body))), ReasonCode: "review", CreatedAt: "2026-01-01T00:00:00Z",
	}
	if err := store.SavePending(pending); err != nil {
		t.Fatal(err)
	}
	if err := store.SavePending(pending); err != nil {
		t.Fatalf("replay: %v", err)
	}
	loaded, err := store.Pending(pending.MessageID)
	if err != nil || loaded.Body != body || loaded.BodyExternal {
		t.Fatalf("Pending external=%v len=%d err=%v", loaded.BodyExternal, len(loaded.Body), err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "approvals", pending.MessageID+".pending.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("<>")) || !bytes.Contains(raw, []byte(`"body_external":true`)) {
		t.Fatalf("pending record = %s", raw)
	}
	conflict := pending
	conflict.Body = body + "<>"
	if err := store.SavePending(conflict); err == nil {
		t.Fatal("conflicting spilled body was accepted")
	}
	loaded, err = store.Pending(pending.MessageID)
	if err != nil || loaded.Body != body {
		t.Fatalf("conflict clobbered body: len=%d err=%v", len(loaded.Body), err)
	}

	inline := pending
	inline.MessageID = "message-2"
	inline.Body = strings.Repeat("a", 400_000)
	if err := store.SavePending(inline); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "approvals", inline.MessageID+".body")); !os.IsNotExist(err) {
		t.Fatalf("inline body created a sidecar: %v", err)
	}
	loaded, err = store.Pending(inline.MessageID)
	if err != nil || loaded.Body != inline.Body {
		t.Fatalf("inline Pending len=%d err=%v", len(loaded.Body), err)
	}
}
