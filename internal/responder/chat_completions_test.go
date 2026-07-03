package responder

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPRespond(t *testing.T) {
	t.Setenv("TURNWIRE_TEST_KEY", "secret-value")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if got := req.Header.Get("Authorization"); got != "Bearer secret-value" {
			t.Fatalf("Authorization = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"hello 🌍\nsecond line"}}]}`))
	}))
	defer server.Close()

	r, err := NewHTTP(HTTPConfig{
		Endpoint:       server.URL,
		Model:          "test-model",
		APIKeyEnv:      "TURNWIRE_TEST_KEY",
		MaxOutputBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	reply, err := r.Respond(context.Background(), "hi")
	if err != nil {
		t.Fatal(err)
	}
	if reply != "hello 🌍\nsecond line" {
		t.Fatalf("reply = %q", reply)
	}
}

func TestHTTPRespondWithResponsesAPI(t *testing.T) {
	t.Setenv("TURNWIRE_TEST_KEY", "secret-value")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if got := req.Header.Get("Authorization"); got != "Bearer secret-value" {
			t.Fatalf("Authorization = %q", got)
		}
		var body struct {
			Model        string `json:"model"`
			Instructions string `json:"instructions"`
			Input        string `json:"input"`
			Store        bool   `json:"store"`
		}
		if err := jsonNewDecoder(req).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Model != "gpt-test" || body.Instructions != systemPrompt || body.Input != "hi" || body.Store {
			t.Fatalf("request = %#v", body)
		}
		_, _ = w.Write([]byte(`{"status":"completed","output":[{"type":"reasoning"},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hello from GPT"}]}]}`))
	}))
	defer server.Close()

	r, err := NewHTTP(HTTPConfig{
		API:            "responses",
		Endpoint:       server.URL,
		Model:          "gpt-test",
		APIKeyEnv:      "TURNWIRE_TEST_KEY",
		MaxOutputBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	reply, err := r.Respond(context.Background(), "hi")
	if err != nil {
		t.Fatal(err)
	}
	if reply != "hello from GPT" {
		t.Fatalf("reply = %q", reply)
	}
}

func TestHTTPResponsesAPIRejectsIncompleteOrMissingText(t *testing.T) {
	tests := map[string]string{
		"incomplete":    `{"status":"incomplete","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"partial"}]}]}`,
		"tool output":   `{"status":"completed","output":[{"type":"function_call"}]}`,
		"wrong role":    `{"status":"completed","output":[{"type":"message","role":"user","content":[{"type":"output_text","text":"no"}]}]}`,
		"wrong content": `{"status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"refusal","refusal":"no"}]}]}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()
			r, err := NewHTTP(HTTPConfig{API: "responses", Endpoint: server.URL, Model: "test", MaxOutputBytes: 32})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := r.Respond(context.Background(), "hello"); !errors.Is(err, ErrInvalidReply) {
				t.Fatalf("error = %v, want ErrInvalidReply", err)
			}
		})
	}
}

func TestHTTPIgnoresAdditionalChoicesWithoutDecodingThem(t *testing.T) {
	const ignoredChoices = 20_000
	body := `{"choices":[{"message":{"content":"first"}}` + strings.Repeat(`,{}`, ignoredChoices) + `]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	r, err := NewHTTP(HTTPConfig{Endpoint: server.URL, Model: "test", MaxOutputBytes: 128})
	if err != nil {
		t.Fatal(err)
	}
	reply, err := r.Respond(context.Background(), "hello")
	if err != nil {
		t.Fatal(err)
	}
	if reply != "first" {
		t.Fatalf("reply = %q", reply)
	}
}

func TestHTTPRejectsMalformedOrEmptyChoices(t *testing.T) {
	tests := map[string]string{
		"missing":          `{}`,
		"null":             `{"choices":null}`,
		"non-array":        `{"choices":{}}`,
		"empty":            `{"choices":[]}`,
		"malformed JSON":   `{"choices":[`,
		"malformed choice": `{"choices":[1]}`,
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()

			r, err := NewHTTP(HTTPConfig{Endpoint: server.URL, Model: "test", MaxOutputBytes: 32})
			if err != nil {
				t.Fatal(err)
			}
			_, err = r.Respond(context.Background(), "hello")
			if !errors.Is(err, ErrInvalidReply) {
				t.Fatalf("error = %v, want ErrInvalidReply", err)
			}
		})
	}
}

func TestHTTPDoesNotSendTools(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body map[string]any
		if err := jsonNewDecoder(req).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if _, ok := body["tools"]; ok {
			t.Fatal("request unexpectedly contains tools")
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer server.Close()

	r, err := NewHTTP(HTTPConfig{Endpoint: server.URL, Model: "test", MaxOutputBytes: 16})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Respond(context.Background(), "$(touch /tmp/nope)"); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPRejectsOversizedReply(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"` + strings.Repeat("x", 33) + `"}}]}`))
	}))
	defer server.Close()
	r, err := NewHTTP(HTTPConfig{Endpoint: server.URL, Model: "test", MaxOutputBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Respond(context.Background(), "hello")
	if !errors.Is(err, ErrReplyTooLarge) {
		t.Fatalf("error = %v", err)
	}
}

func TestHTTPRejectsMalformedUTF8Reply(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(append(
			[]byte(`{"choices":[{"message":{"content":"`),
			append([]byte{0xff}, []byte(`"}}]}`)...)...,
		))
	}))
	defer server.Close()
	r, err := NewHTTP(HTTPConfig{Endpoint: server.URL, Model: "test", MaxOutputBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Respond(context.Background(), "hello")
	if !errors.Is(err, ErrInvalidReply) {
		t.Fatalf("error = %v, want ErrInvalidReply", err)
	}
}

func TestHTTPRejectsLoneSurrogateReply(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"\ud800"}}]}`))
	}))
	defer server.Close()
	r, err := NewHTTP(HTTPConfig{Endpoint: server.URL, Model: "test", MaxOutputBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Respond(context.Background(), "hello")
	if !errors.Is(err, ErrInvalidReply) {
		t.Fatalf("error = %v, want ErrInvalidReply", err)
	}
}

func TestHTTPRejectsUnsafeOutputLimit(t *testing.T) {
	_, err := NewHTTP(HTTPConfig{
		Endpoint:       "http://127.0.0.1:1/v1/chat/completions",
		Model:          "test",
		MaxOutputBytes: maxSupportedOutputBytes + 1,
	})
	if err == nil {
		t.Fatal("NewHTTP accepted an unsafe output limit")
	}
}

func TestNewHTTPRejectsEmptyHostnameAuthority(t *testing.T) {
	_, err := NewHTTP(HTTPConfig{
		Endpoint:       "https://:443/v1/chat/completions",
		Model:          "test",
		MaxOutputBytes: 32,
	})
	if err == nil {
		t.Fatal("NewHTTP accepted an endpoint without a hostname")
	}
}

func TestHTTPRejectsMissingKey(t *testing.T) {
	r, err := NewHTTP(HTTPConfig{
		Endpoint:       "http://127.0.0.1:1/v1/chat/completions",
		Model:          "test",
		APIKeyEnv:      "TURNWIRE_MISSING_KEY",
		MaxOutputBytes: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Respond(context.Background(), "hello")
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("error = %v", err)
	}
}

func jsonNewDecoder(req *http.Request) *json.Decoder {
	return json.NewDecoder(req.Body)
}
