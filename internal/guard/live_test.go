package guard

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestLiveOpenAIGuardModels(t *testing.T) {
	if os.Getenv("TURNWIRE_LIVE_OPENAI") != "1" {
		t.Skip("set TURNWIRE_LIVE_OPENAI=1 for billable live guard probes")
	}
	if os.Getenv("OPENAI_API_KEY") == "" {
		t.Skip("OPENAI_API_KEY is not configured")
	}
	tests := []struct {
		model     string
		retention string
	}{
		{model: "gpt-5.4-2026-03-05", retention: "in_memory"},
		{model: "gpt-5.5-2026-04-23", retention: "24h"},
	}
	for _, test := range tests {
		t.Run(test.model, func(t *testing.T) {
			client, err := NewHTTP(HTTPConfig{
				Endpoint: "https://api.openai.com/v1/responses", Model: test.model,
				APIKeyEnv: "OPENAI_API_KEY", PromptCacheRetention: test.retention,
			})
			if err != nil { t.Fatal(err) }
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			result, err := client.Evaluate(ctx, Input{
				Direction: "outbound", Source: "work", Destination: "personal",
				Text: "Routine coordination: move tomorrow's meeting to 10:30.",
				Policy: "Allow routine scheduling and coordination without secrets or sensitive data.",
			})
			if err != nil { t.Fatal(err) }
			if result.Model == "" || result.ResponseID == "" || result.ProviderRequestID == "" { t.Fatalf("incomplete provider evidence: %#v", result) }
			if result.Decision != DecisionAllow && result.Decision != DecisionReview && result.Decision != DecisionDeny { t.Fatalf("invalid decision: %#v", result) }
		})
	}
}
