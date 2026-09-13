package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/openclaw/turnwire/internal/config"
)

func TestInitHonorsExplicitGuardOverrides(t *testing.T) {
	for _, test := range []struct {
		name      string
		flags     []string
		apiKey    string
		remote    bool
		retention string
	}{
		{"defaults", nil, "OPENAI_API_KEY", true, "in_memory"},
		{"empty and false", []string{"--endpoint=http://127.0.0.1:1/v1/responses", "--api-key-env=", "--allow-remote=false", "--prompt-cache-retention="}, "", false, ""},
		{"GPT-5.5 default retention", []string{"--model=gpt-5.5-2026-04-23"}, "OPENAI_API_KEY", true, "24h"},
		{"GPT-5.5 explicit empty retention", []string{"--model=gpt-5.5-2026-04-23", "--prompt-cache-retention="}, "OPENAI_API_KEY", true, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.json")
			args := []string{"--config", path, "--data-dir", filepath.Join(dir, "state"), "init", "--identity=work"}
			args = append(args, test.flags...)
			if code := Run(context.Background(), args, nil, io.Discard, io.Discard); code != 0 {
				t.Fatalf("init exit=%d", code)
			}
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Guard.APIKeyEnv != test.apiKey || cfg.Guard.AllowRemote != test.remote || cfg.Guard.PromptCacheRetention != test.retention {
				t.Fatalf("guard overrides lost: API env=%q remote=%t retention=%q", cfg.Guard.APIKeyEnv, cfg.Guard.AllowRemote, cfg.Guard.PromptCacheRetention)
			}
			if cfg.Deployment.ID != "work" {
				t.Fatalf("default deployment=%q", cfg.Deployment.ID)
			}
		})
	}
}

func TestInitRejectsExplicitInvalidSettings(t *testing.T) {
	for _, flag := range []string{"--endpoint=", "--model=", "--policy=", "--policy-version=", "--deployment-id=", "--allow-remote=false"} {
		t.Run(flag, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.json")
			args := []string{"--config", path, "--data-dir", filepath.Join(dir, "state"), "init", flag}
			if code := Run(context.Background(), args, nil, io.Discard, io.Discard); code != 2 {
				t.Fatalf("init exit=%d, want usage error", code)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("invalid init wrote config: %v", err)
			}
		})
	}
}
