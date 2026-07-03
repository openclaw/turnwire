package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"testing"
)

func TestDefaultIsPinnedFailClosedOpenAIGuard(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Version != 2 || cfg.Guard.API != "responses" || cfg.Guard.Model != "gpt-5.4-2026-03-05" {
		t.Fatalf("default guard = %#v", cfg.Guard)
	}
	if cfg.Guard.PromptCacheRetention != "in_memory" || !cfg.Guard.AllowRemote {
		t.Fatalf("default data controls = %#v", cfg.Guard)
	}
	if cfg.Identity.Peers == nil || len(cfg.Identity.Peers) != 0 {
		t.Fatalf("default peers = %#v", cfg.Identity.Peers)
	}
}

func TestGPT55RejectsUnsupportedInMemoryCache(t *testing.T) {
	cfg := Default()
	cfg.Guard.Model = "gpt-5.5-2026-04-23"
	if err := cfg.Validate(); err == nil {
		t.Fatal("GPT-5.5 accepted in_memory prompt cache retention")
	}
	cfg.Guard.PromptCacheRetention = "24h"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteGuardEndpointIsRestrictedToOpenAI(t *testing.T) {
	cfg := Default()
	cfg.Guard.Endpoint = "https://example.com/v1/responses"
	if err := cfg.Validate(); err == nil {
		t.Fatal("arbitrary remote guard endpoint accepted")
	}
	cfg.Guard.Endpoint = "http://127.0.0.1:8080/v1/responses"
	cfg.Guard.AllowRemote = false
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestPeerKeysAreNamedUniqueEd25519Keys(t *testing.T) {
	cfg := Default()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Identity.Peers = []PeerConfig{{Name: "personal", PublicKey: base64.RawStdEncoding.EncodeToString(publicKey)}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.Identity.Peers = append(cfg.Identity.Peers, cfg.Identity.Peers[0])
	if err := cfg.Validate(); err == nil {
		t.Fatal("duplicate peer accepted")
	}
}

func TestWriteLoadRoundTrip(t *testing.T) {
	cfg := Default()
	cfg.Identity.Name = "work"
	path := filepath.Join(t.TempDir(), "config", "config.json")
	if err := Write(path, cfg, false); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Identity.Name != "work" || loaded.Guard.Model != cfg.Guard.Model {
		t.Fatalf("loaded = %#v", loaded)
	}
}
