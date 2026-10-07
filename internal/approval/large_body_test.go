package approval

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestSavePendingLargeEscapedBody(t *testing.T) {
	store, err := Open(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	body := strings.Repeat("<>", 200_000)
	pending := Pending{MessageID: "large-message", Direction: "outbound", Source: "work", Destination: "personal", Body: body, BodySHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(body)))}
	if err := store.SavePending(pending); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Pending(pending.MessageID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != pending {
		t.Fatal("pending body or binding changed")
	}
}
