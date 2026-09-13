package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/openclaw/turnwire/internal/audit"
)

func TestExportDetailsKeepsReconciliationEvidenceAndDropsExplanations(t *testing.T) {
	details := map[string]string{
		"provider_request_id":  "request-id",
		"provider_response_id": "response-id",
		"envelope_sha256":      "envelope-hash",
		"acknowledgement":      `{"signature":"signed"}`,
		"explanation":          "derived sensitive explanation",
		"unexpected":           "private metadata",
	}
	exported := exportDetails(details)
	for _, key := range []string{"provider_request_id", "provider_response_id", "envelope_sha256", "acknowledgement"} {
		if exported[key] != details[key] {
			t.Fatalf("export omitted %s", key)
		}
	}
	for _, key := range []string{"explanation", "unexpected"} {
		if _, exists := exported[key]; exists {
			t.Fatalf("export leaked %s", key)
		}
	}
}

func TestScanLogMatchesBudgetsDetailsAndFiltersBeforeAccounting(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	log, err := audit.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	for _, test := range []struct{ event, exchange, request, message, payload string }{
		{"first", "group", "request-1", "message-1", "12345678"},
		{"second", "group", "request-2", "message-2", "12345678"},
		{"unrelated", "other", "other-request", "other-message", strings.Repeat("x", 80)},
	} {
		_, err := log.Append(audit.Event{EventID: test.event, ExchangeID: test.exchange, RequestID: test.request,
			ConversationID: "conversation", Type: "fixture", Status: "recorded",
			Details: map[string]string{"payload": test.payload, "message_id": test.message}})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"first", "request-1", "message-1"} {
		entries, err := scanLogMatches(dir, id, 40)
		if err != nil {
			t.Fatalf("single match %s: %v", id, err)
		}
		if len(entries) != 1 || entries[0].EventID != "first" {
			t.Fatalf("wrong match for %s", id)
		}
	}
	if _, err := scanLogMatches(dir, "group", 40); err == nil {
		t.Fatal("metadata-only matches bypassed the display budget")
	}
}
