package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openclaw/turnwire/internal/approval"
	"github.com/openclaw/turnwire/internal/audit"
	"github.com/openclaw/turnwire/internal/config"
	"github.com/openclaw/turnwire/internal/identity"
)

func TestInitCreatesIdentityAndPeerAdd(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config", "config.json")
	dataDir := filepath.Join(root, "state")
	args := []string{"--config", configPath, "--data-dir", dataDir, "init", "--identity", "work", "--model", "gpt-5.5-2026-04-23"}
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), args, &bytes.Buffer{}, &stdout, &stderr); code != 0 {
		t.Fatalf("init code=%d stderr=%s", code, stderr.String())
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Identity.Name != "work" || cfg.Guard.Model != "gpt-5.5-2026-04-23" || cfg.Guard.PromptCacheRetention != "24h" {
		t.Fatalf("config=%#v", cfg)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerKey := base64.RawStdEncoding.EncodeToString(publicKey)
	stdout.Reset()
	stderr.Reset()
	peerArgs := []string{"--config", configPath, "--data-dir", dataDir, "peer", "add", "personal", peerKey}
	if code := Run(context.Background(), peerArgs, &bytes.Buffer{}, &stdout, &stderr); code != 0 {
		t.Fatalf("peer code=%d stderr=%s", code, stderr.String())
	}
	cfg, err = config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Identity.Peers) != 1 || cfg.Identity.Peers[0].Name != "personal" {
		t.Fatalf("peers=%#v", cfg.Identity.Peers)
	}
}

func TestForcedInitCannotOverwriteManagedState(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.json")
	dataDir := filepath.Join(root, "state")
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"--config", configPath, "--data-dir", dataDir, "init", "--identity", "work"}, &bytes.Buffer{}, &stdout, &stderr); code != 0 {
		t.Fatalf("init code=%d stderr=%s", code, stderr.String())
	}
	auditDir := filepath.Join(dataDir, "audit")
	signer, err := identity.LoadOrCreate(auditDir, "work", false)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := signer.PublicKey()
	store, err := approval.Open(auditDir, false)
	if err != nil {
		t.Fatal(err)
	}
	pending := approval.Pending{MessageID: "message-1", Direction: "outbound", Source: "work", Destination: "personal", Body: "review me", BodySHA256: "abc", ReasonCode: "review", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := store.SavePending(pending); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	targets := []string{
		filepath.Join(auditDir, "identity.ed25519"),
		filepath.Join(auditDir, "approvals", pending.MessageID+".pending.json"),
	}
	for _, target := range targets {
		stdout.Reset()
		stderr.Reset()
		args := []string{"--config", target, "--data-dir", dataDir, "init", "--identity", "work", "--force"}
		if code := Run(context.Background(), args, &bytes.Buffer{}, &stdout, &stderr); code == 0 {
			t.Fatalf("forced init overwrote managed state %s", target)
		}
	}
	signer, err = identity.LoadOrCreate(auditDir, "work", false)
	if err != nil || signer.PublicKey() != publicKey {
		t.Fatalf("identity changed after forced init: key=%q err=%v", signer.PublicKey(), err)
	}
	store, err = approval.Open(auditDir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	loaded, err := store.Pending(pending.MessageID)
	if err != nil || loaded.Body != pending.Body {
		t.Fatalf("pending approval changed after forced init: %#v err=%v", loaded, err)
	}
}

func TestVerifyWritableAuditDirRejectsExhaustedQuota(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	log, err := audit.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = log.Append(audit.Event{
		EventID:        "seed",
		ExchangeID:     "exchange",
		RequestID:      "request",
		ConversationID: "conversation",
		Type:           "seed",
		Status:         "ok",
		Text:           "durable",
	})
	if err != nil {
		t.Fatal(err)
	}
	used, _, err := log.Usage()
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	if err := verifyWritableAuditDir(dir, used); !errors.Is(err, audit.ErrQuotaExceeded) {
		t.Fatalf("verifyWritableAuditDir() error = %v, want ErrQuotaExceeded", err)
	}
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestApproveAbortsWhenPendingMessageCannotBeDisplayed(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.json")
	auditDir := filepath.Join(root, "audit")
	cfg := config.Default()
	cfg.Identity.Name = "work"
	cfg.AuditDir = auditDir
	if err := config.Write(configPath, cfg, false); err != nil {
		t.Fatal(err)
	}
	store, err := approval.Open(auditDir, true)
	if err != nil {
		t.Fatal(err)
	}
	pending := approval.Pending{MessageID: "message-1", Direction: "outbound", Source: "work", Destination: "personal", Body: "exact review text", BodySHA256: "abc", ReasonCode: "review", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := store.SavePending(pending); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	injected := errors.New("display failed")
	err = runApprove([]string{"--yes", pending.MessageID}, options{configPath: configPath}, &bytes.Buffer{}, failingWriter{err: injected})
	if !errors.Is(err, injected) {
		t.Fatalf("runApprove() error = %v, want display failure", err)
	}
	store, err = approval.Open(auditDir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if ok, err := store.IsApproved(pending.Binding()); err != nil || ok {
		t.Fatalf("approval after display failure = %v, %v", ok, err)
	}
}

func TestApproveEscapesTerminalControlSequences(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.json")
	auditDir := filepath.Join(root, "audit")
	cfg := config.Default()
	cfg.Identity.Name = "work"
	cfg.AuditDir = auditDir
	if err := config.Write(configPath, cfg, false); err != nil {
		t.Fatal(err)
	}
	store, err := approval.Open(auditDir, true)
	if err != nil {
		t.Fatal(err)
	}
	pending := approval.Pending{MessageID: "message-1", Direction: "inbound", Source: "personal", Destination: "work", Body: "safe\x1b[2Jforged prompt", BodySHA256: "abc", ReasonCode: "review", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := store.SavePending(pending); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	err = runApprove([]string{pending.MessageID}, options{configPath: configPath}, bytes.NewBufferString("n\n"), &stdout)
	if err == nil {
		t.Fatal("runApprove() unexpectedly approved message")
	}
	if strings.Contains(stdout.String(), "\x1b") || !strings.Contains(stdout.String(), `\x1b[2J`) {
		t.Fatalf("approval display was not terminal-safe: %q", stdout.String())
	}
}

func TestScanLogEntriesFailsWhenRequestedWindowExceedsBudget(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	log, err := audit.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i, text := range []string{"first-large", "second-large"} {
		_, err := log.Append(audit.Event{EventID: fmt.Sprintf("event-%d", i), ExchangeID: "exchange", RequestID: fmt.Sprintf("request-%d", i), ConversationID: "conversation", Type: "message", Status: "ok", Text: text})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := scanLogEntries(dir, "", "", 2, len("second-large")); err == nil {
		t.Fatal("scanLogEntries() silently truncated the requested audit window")
	}
}

var _ io.Writer = failingWriter{}
