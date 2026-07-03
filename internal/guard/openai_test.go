package guard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResponsesGuardUsesStrictNoToolDataControls(t *testing.T) {
	var request map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		w.Header().Set("x-request-id", "req_guard_123")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id": "resp_guard_123", "model": "gpt-5.4-2026-03-05", "status": "completed",
			"output": []any{map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": `{"classification":"allow_coordination","explanation":"Routine coordination."}`}}}},
		})
	}))
	defer server.Close()
	model, err := NewHTTP(HTTPConfig{Endpoint: server.URL, Model: "gpt-5.4-2026-03-05", PromptCacheRetention: "in_memory", Client: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := model.Evaluate(context.Background(), Input{Direction: "outbound", Source: "work", Destination: "personal", Text: "meeting at 10", Policy: "coordination only"})
	if err != nil {
		t.Fatal(err)
	}
	if evaluation.Decision != DecisionAllow || evaluation.ProviderRequestID != "req_guard_123" || evaluation.ResponseID != "resp_guard_123" {
		t.Fatalf("evaluation = %#v", evaluation)
	}
	if request["store"] != false || request["background"] != false || request["prompt_cache_retention"] != "in_memory" {
		t.Fatalf("data controls = %#v", request)
	}
	tools, ok := request["tools"].([]any)
	if !ok || len(tools) != 0 {
		t.Fatalf("tools = %#v", request["tools"])
	}
	text := request["text"].(map[string]any)
	format := text["format"].(map[string]any)
	if format["type"] != "json_schema" || format["strict"] != true {
		t.Fatalf("format = %#v", format)
	}
	var input Input
	if err := json.Unmarshal([]byte(request["input"].(string)), &input); err != nil {
		t.Fatal(err)
	}
	if input.Text != "meeting at 10" {
		t.Fatalf("input = %#v", input)
	}
}

func TestValidateVerdictRejectsSensitiveAllowAndReview(t *testing.T) {
	tests := []Verdict{
		{Decision: DecisionAllow, ReasonCode: "secret", DataClasses: []string{"public"}, Explanation: "Contradictory."},
		{Decision: DecisionAllow, ReasonCode: "allowed", DataClasses: []string{"credential"}, Explanation: "Contradictory."},
		{Decision: DecisionReview, ReasonCode: "credential", DataClasses: []string{"credential"}, Explanation: "Contradictory."},
		{Decision: DecisionDeny, ReasonCode: "allowed", DataClasses: []string{"public"}, Explanation: "Contradictory."},
	}
	for _, verdict := range tests {
		if err := validateVerdict(verdict); err == nil || !strings.Contains(err.Error(), "inconsistent") {
			t.Fatalf("validateVerdict(%#v) error = %v, want inconsistency", verdict, err)
		}
	}
	if err := validateVerdict(Verdict{Decision: DecisionAllow, ReasonCode: "allowed", DataClasses: []string{"coordination"}, Explanation: "Routine."}); err != nil {
		t.Fatalf("valid allow rejected: %v", err)
	}
}

func TestResponsesGuardRejectsDifferentReturnedModel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("x-request-id", "req_guard_123")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id": "resp_guard_123", "model": "gpt-5.4", "status": "completed",
			"output": []any{map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": `{"classification":"allow_coordination","explanation":"Routine coordination."}`}}}},
		})
	}))
	defer server.Close()
	model, err := NewHTTP(HTTPConfig{Endpoint: server.URL, Model: "gpt-5.4-2026-03-05", Client: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := model.Evaluate(context.Background(), Input{Text: "meeting at 10"}); err == nil || !strings.Contains(err.Error(), "matching provider audit identifiers") {
		t.Fatalf("model mismatch error = %v", err)
	}
}

func TestClassificationMappingCannotProduceContradictoryVerdict(t *testing.T) {
	for _, classification := range classificationNames {
		verdict, err := verdictForClassification(modelVerdict{Classification: classification, Explanation: "Bounded explanation."})
		if err != nil {
			t.Fatalf("classification %q: %v", classification, err)
		}
		if err := validateVerdict(verdict); err != nil {
			t.Fatalf("classification %q produced %#v: %v", classification, verdict, err)
		}
	}
}
