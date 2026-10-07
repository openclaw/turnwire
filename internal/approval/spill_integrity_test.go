package approval

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func spilledPending() Pending {
	body := strings.Repeat("<>", 200_000)
	return Pending{MessageID: "spilled", Direction: "outbound", Source: "work", Destination: "personal", Body: body, BodySHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(body)))}
}

func TestSpilledPendingRejectsDamagedBody(t *testing.T) {
	for _, damage := range []string{"missing", "empty", "changed", "invalid UTF-8", "oversized", "permissions", "symlink", "ambiguous"} {
		t.Run(damage, func(t *testing.T) {
			dir := t.TempDir()
			store, err := Open(dir, true)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			pending := spilledPending()
			if err := store.SavePending(pending); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "approvals", pending.MessageID+".body")
			switch damage {
			case "missing":
				err = os.Remove(path)
			case "empty":
				err = os.WriteFile(path, nil, 0o600)
			case "changed":
				err = os.WriteFile(path, []byte("different review text"), 0o600)
			case "invalid UTF-8":
				err = os.WriteFile(path, []byte{0xff}, 0o600)
			case "oversized":
				err = os.WriteFile(path, []byte(strings.Repeat("x", (2<<20)+1)), 0o600)
			case "permissions":
				err = os.Chmod(path, 0o644)
			case "symlink":
				if err = os.Rename(path, path+".target"); err == nil {
					err = os.Symlink(path+".target", path)
				}
			case "ambiguous":
				pending.Body = "also inline"
				pending.BodyExternal = true
				var data []byte
				data, err = json.Marshal(pending)
				if err == nil {
					err = os.WriteFile(filepath.Join(dir, "approvals", pending.MessageID+".pending.json"), data, 0o600)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Pending(pending.MessageID); err == nil {
				t.Fatal("display accepted damaged pending body")
			}
			if err := store.SavePending(spilledPending()); err == nil {
				t.Fatal("replay accepted damaged pending body")
			}
		})
	}
}

func TestSpilledPendingRecoversBodyOnlyWriteAndReopens(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	pending := spilledPending()
	// A crash between the durable body and metadata writes leaves only the body.
	if err := store.store.Create(pending.MessageID+".body", []byte(pending.Body)); err != nil {
		t.Fatal(err)
	}
	conflict := pending
	conflict.Body += "<>"
	if err := store.SavePending(conflict); err == nil {
		t.Fatal("conflicting retry replaced orphaned body")
	}
	if err := store.SavePending(pending); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	loaded, err := store.Pending(pending.MessageID)
	if err != nil || loaded != pending {
		t.Fatalf("reopened pending differs: %v", err)
	}
	if err := store.Approve(loaded.Binding(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if ok, err := store.IsApproved(pending.Binding()); err != nil || !ok {
		t.Fatalf("approval = %v, %v", ok, err)
	}
}
