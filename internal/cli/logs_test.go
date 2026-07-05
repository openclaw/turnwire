package cli

import "testing"

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
