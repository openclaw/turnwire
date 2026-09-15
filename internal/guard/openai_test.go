package guard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

func TestResponsesGuardRequiresSingleCompleteVerdict(t *testing.T) {
	allow := `{"type":"output_text","text":"{\"classification\":\"allow_coordination\",\"explanation\":\"Routine.\"}"}`
	deny := `{"type":"output_text","text":"{\"classification\":\"deny_policy_violation\",\"explanation\":\"Denied.\"}"}`
	message := func(parts string) string {
		return `{"type":"message","role":"assistant","content":[` + parts + `]}`
	}
	tests := []struct {
		name   string
		output string
		valid  bool
	}{
		{"single verdict", `[` + message(allow) + `]`, true},
		{"reasoning and verdict", `[{"type":"reasoning","summary":[]},` + message(allow) + `]`, true},
		{"conflicting parts", `[` + message(allow+`,`+deny) + `]`, false},
		{"conflicting messages", `[` + message(allow) + `,` + message(deny) + `]`, false},
		{"refusal after allow", `[` + message(allow+`,{"type":"refusal","refusal":"Denied."}`) + `]`, false},
		{"refusal before allow", `[` + message(`{"type":"refusal","refusal":"Denied."},`+allow) + `]`, false},
		{"unexpected tool call", `[` + message(allow) + `,{"type":"function_call","name":"unexpected"}]`, false},
		{"malformed trailing item", `[` + message(allow) + `,42]`, false},
		{"duplicate content", `[{"type":"message","role":"assistant","content":[{"type":"refusal"}],"content":[` + allow + `]}]`, false},
		{"case aliased content", `[{"type":"message","role":"assistant","Content":[{"type":"refusal"}],"content":[` + allow + `]}]`, false},
		{"duplicate type", `[` + message(allow) + `,{"type":"function_call","type":"reasoning"}]`, false},
		{"duplicate classification", `[` + message(`{"type":"output_text","text":"{\"classification\":\"deny_secret\",\"classification\":\"allow_public\",\"explanation\":\"Routine.\"}"}`) + `]`, false},
		{"wrong role", `[{"type":"message","role":"user","content":[` + allow + `]}]`, false},
		{"empty output", `[]`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("x-request-id", "req_synthetic")
				json.NewEncoder(w).Encode(map[string]any{
					"id": "resp_synthetic", "model": "gpt-5.4-2026-03-05", "status": "completed",
					"output": json.RawMessage(tt.output),
				})
			}))
			defer server.Close()
			model, err := NewHTTP(HTTPConfig{Endpoint: server.URL, Model: "gpt-5.4-2026-03-05", Client: server.Client()})
			if err != nil {
				t.Fatal(err)
			}
			evaluation, err := model.Evaluate(context.Background(), Input{Text: "Synthetic scheduling note."})
			if tt.valid {
				if err != nil || evaluation.Decision != DecisionAllow {
					t.Fatalf("valid output: evaluation = %#v, error = %v", evaluation, err)
				}
			} else if err == nil || evaluation.Decision != "" {
				t.Fatalf("invalid output released a verdict: evaluation = %#v, error = %v", evaluation, err)
			}
		})
	}
}

func TestNewHTTPDefaultClientHasTimeout(t *testing.T) {
	model, err := NewHTTP(HTTPConfig{Endpoint: "https://example.com/v1/responses", Model: "gpt-5.4-2026-03-05"})
	if err != nil {
		t.Fatal(err)
	}
	if model.client.Timeout != defaultHTTPClientTimeout {
		t.Fatalf("default guard HTTP client Timeout = %s, want %s", model.client.Timeout, defaultHTTPClientTimeout)
	}
}

func TestNewHTTPHonorsConfiguredTimeout(t *testing.T) {
	configured := 5 * time.Minute
	model, err := NewHTTP(HTTPConfig{
		Endpoint: "https://example.com/v1/responses",
		Model:    "gpt-5.4-2026-03-05",
		Timeout:  configured,
	})
	if err != nil {
		t.Fatal(err)
	}
	if model.client.Timeout != configured {
		t.Fatalf("guard HTTP client Timeout = %s, want %s", model.client.Timeout, configured)
	}
}

type stubRoundTripper struct{}

func (stubRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, http.ErrNotSupported
}

func TestNewHTTPDoesNotPanicWhenDefaultTransportIsReplaced(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	http.DefaultTransport = stubRoundTripper{}
	model, err := NewHTTP(HTTPConfig{Endpoint: "https://example.com/v1/responses", Model: "gpt-5.4-2026-03-05"})
	if err != nil {
		t.Fatal(err)
	}
	if model.client == nil || model.client.Timeout != defaultHTTPClientTimeout {
		t.Fatalf("swapped-transport client Timeout = %s, want %s", model.client.Timeout, defaultHTTPClientTimeout)
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
