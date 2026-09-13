package approval

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAllApprovalReadersRejectMalformedRecords(t *testing.T) {
	operations := []struct {
		name, suffix string
		read         func(*Store, Pending) error
	}{
		{"pending", ".pending.json", func(s *Store, p Pending) error { _, err := s.Pending(p.MessageID); return err }},
		{"pending replay", ".pending.json", func(s *Store, p Pending) error { return s.SavePending(p) }},
		{"approved", ".approved.json", func(s *Store, p Pending) error { _, err := s.IsApproved(p.Binding()); return err }},
		{"approval replay", ".approved.json", func(s *Store, p Pending) error { return s.Approve(p.Binding(), time.Now()) }},
	}
	corruptions := []struct {
		name   string
		change func([]byte) []byte
	}{
		{"null record", func([]byte) []byte { return []byte("null") }},
		{"second value", func(data []byte) []byte { return append(data, []byte("\n{}")...) }},
		{"trailing garbage", func(data []byte) []byte { return append(data, []byte("junk")...) }},
		{"invalid UTF-8", func(data []byte) []byte { return append(data, 0xff) }},
		{"unknown field", func(data []byte) []byte { return append(data[:len(data)-1], []byte(",\"extra\":true}")...) }},
	}
	for _, operation := range operations {
		for _, corruption := range corruptions {
			t.Run(operation.name+"/"+corruption.name, func(t *testing.T) {
				dir := t.TempDir()
				store, err := Open(dir, true)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = store.Close() })
				pending := Pending{MessageID: "message", Direction: "outbound", Source: "work", Destination: "personal", Body: "Synthetic note.", BodySHA256: "fixture-hash", ReasonCode: "ambiguous", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
				if err := store.SavePending(pending); err != nil {
					t.Fatal(err)
				}
				if err := store.Approve(pending.Binding(), time.Now()); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(dir, "approvals", pending.MessageID+operation.suffix)
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, corruption.change(data), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := operation.read(store, pending); err == nil {
					t.Fatal("accepted malformed approval record")
				}
			})
		}
	}
}
