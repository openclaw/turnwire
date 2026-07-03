package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openclaw/turnwire/internal/audit"
	"github.com/openclaw/turnwire/internal/buildinfo"
	"github.com/openclaw/turnwire/internal/config"
	"github.com/openclaw/turnwire/internal/responder"
)

func TestHelpVersionAndUsageExitCodes(t *testing.T) {
	code, stdout, stderr := invoke(t)
	if code != 0 || !strings.Contains(stdout, "turnwire [global flags]") || stderr != "" {
		t.Fatalf("help: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	code, stdout, stderr = invoke(t, "version", "--json")
	if code != 0 || stderr != "" {
		t.Fatalf("version: code=%d stderr=%q", code, stderr)
	}
	var version struct {
		Version   string `json:"version"`
		GoVersion string `json:"go_version"`
	}
	if err := json.Unmarshal([]byte(stdout), &version); err != nil {
		t.Fatalf("decode version: %v", err)
	}
	if version.Version == "" || version.GoVersion == "" {
		t.Fatalf("version = %#v", version)
	}
	code, stdout, stderr = invoke(t, "--version")
	if code != 0 || !strings.HasPrefix(stdout, "turnwire ") || stderr != "" {
		t.Fatalf("root version: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	code, _, stderr = invoke(t, "not-a-command")
	if code != 2 || !strings.Contains(stderr, "unknown command") {
		t.Fatalf("unknown command: code=%d stderr=%q", code, stderr)
	}
	code, _, stderr = invoke(t, "--quiet", "--verbose", "version")
	if code != 2 || !strings.Contains(stderr, "cannot be used together") {
		t.Fatalf("conflicting flags: code=%d stderr=%q", code, stderr)
	}
}

func TestFormatVersionLineReportsOnlyKnownVCSState(t *testing.T) {
	base := buildinfo.Info{
		Version:   "v1.2.3",
		Commit:    "0123456789abcdef",
		BuildTime: "2026-06-28T12:34:56Z",
		GoVersion: "go-test",
	}
	if got := formatVersionLine(base); strings.Contains(got, "clean") || strings.Contains(got, "modified") {
		t.Fatalf("unknown VCS state was presented as known: %q", got)
	}

	clean := false
	base.Modified = &clean
	if got := formatVersionLine(base); !strings.Contains(got, ", clean,") || strings.Contains(got, "modified") {
		t.Fatalf("known-clean version line = %q", got)
	}

	modified := true
	base.Modified = &modified
	if got := formatVersionLine(base); !strings.Contains(got, ", modified,") || strings.Contains(got, "clean") {
		t.Fatalf("known-modified version line = %q", got)
	}
}

func TestNonLogCLIOutputFailuresReturnExitFailure(t *testing.T) {
	writeFailure := errors.New("test CLI output failure")
	tests := []struct {
		name string
		args []string
	}{
		{name: "root help", args: nil},
		{name: "global help", args: []string{"--help"}},
		{name: "global version", args: []string{"--version"}},
		{name: "help command", args: []string{"help", "version"}},
		{name: "version", args: []string{"version"}},
		{name: "version JSON", args: []string{"version", "--json"}},
		{name: "init flag help", args: []string{"init", "--help"}},
		{name: "doctor flag help", args: []string{"doctor", "--help"}},
		{name: "serve flag help", args: []string{"serve", "--help"}},
		{name: "version flag help", args: []string{"version", "--help"}},
	}
	for _, test := range tests {
		t.Run(test.name+" failure", func(t *testing.T) {
			var stderr bytes.Buffer
			writer := &failAfterWriter{err: writeFailure}
			code := Run(context.Background(), test.args, strings.NewReader(""), writer, &stderr)
			if code != 1 || !strings.Contains(stderr.String(), writeFailure.Error()) {
				t.Fatalf("code=%d stderr=%q", code, stderr.String())
			}
		})
		t.Run(test.name+" short", func(t *testing.T) {
			var stderr bytes.Buffer
			code := Run(context.Background(), test.args, strings.NewReader(""), shortOutputWriter{}, &stderr)
			if code != 1 || !strings.Contains(stderr.String(), io.ErrShortWrite.Error()) {
				t.Fatalf("code=%d stderr=%q", code, stderr.String())
			}
		})
	}
}

func TestInitStatusPropagatesEveryWriteFailure(t *testing.T) {
	writeFailure := errors.New("test init output failure")
	for successfulWrites := 0; successfulWrites < 4; successfulWrites++ {
		t.Run(strconv.Itoa(successfulWrites), func(t *testing.T) {
			root := t.TempDir()
			configPath := filepath.Join(root, "config.json")
			dataDir := filepath.Join(root, "state")
			writer := &failAfterWriter{remaining: successfulWrites, err: writeFailure}
			var stderr bytes.Buffer
			code := Run(
				context.Background(),
				[]string{"--config", configPath, "--data-dir", dataDir, "init"},
				strings.NewReader(""),
				writer,
				&stderr,
			)
			if code != 1 || !strings.Contains(stderr.String(), writeFailure.Error()) {
				t.Fatalf("code=%d stderr=%q", code, stderr.String())
			}
			if _, err := config.Load(configPath); err != nil {
				t.Fatalf("init did not finish before status failure: %v", err)
			}
		})
	}

	t.Run("short write", func(t *testing.T) {
		root := t.TempDir()
		var stderr bytes.Buffer
		code := Run(
			context.Background(),
			[]string{
				"--config", filepath.Join(root, "config.json"),
				"--data-dir", filepath.Join(root, "state"),
				"init",
			},
			strings.NewReader(""),
			shortOutputWriter{},
			&stderr,
		)
		if code != 1 || !strings.Contains(stderr.String(), io.ErrShortWrite.Error()) {
			t.Fatalf("code=%d stderr=%q", code, stderr.String())
		}
	})

	t.Run("quiet suppresses status", func(t *testing.T) {
		root := t.TempDir()
		var stderr bytes.Buffer
		code := Run(
			context.Background(),
			[]string{
				"--quiet",
				"--config", filepath.Join(root, "config.json"),
				"--data-dir", filepath.Join(root, "state"),
				"init",
			},
			strings.NewReader(""),
			&failAfterWriter{err: writeFailure},
			&stderr,
		)
		if code != 0 || stderr.String() != "" {
			t.Fatalf("code=%d stderr=%q", code, stderr.String())
		}
	})
}

func TestDoctorOutputFailuresReturnExitFailure(t *testing.T) {
	configPath, dataDir := initializeTestMailbox(t)
	base := []string{"--config", configPath, "--data-dir", dataDir, "doctor"}
	writeFailure := errors.New("test doctor output failure")
	for successfulWrites := 0; successfulWrites < 4; successfulWrites++ {
		t.Run("human line "+strconv.Itoa(successfulWrites), func(t *testing.T) {
			var stderr bytes.Buffer
			writer := &failAfterWriter{remaining: successfulWrites, err: writeFailure}
			code := Run(context.Background(), base, strings.NewReader(""), writer, &stderr)
			if code != 1 || !strings.Contains(stderr.String(), writeFailure.Error()) {
				t.Fatalf("code=%d stderr=%q", code, stderr.String())
			}
		})
	}
	for _, test := range []struct {
		name   string
		args   []string
		writer io.Writer
		want   string
	}{
		{name: "human short", args: base, writer: shortOutputWriter{}, want: io.ErrShortWrite.Error()},
		{name: "JSON failure", args: append(append([]string{}, base...), "--json"), writer: &failAfterWriter{err: writeFailure}, want: writeFailure.Error()},
		{name: "JSON short", args: append(append([]string{}, base...), "--json"), writer: shortOutputWriter{}, want: io.ErrShortWrite.Error()},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stderr bytes.Buffer
			code := Run(context.Background(), test.args, strings.NewReader(""), test.writer, &stderr)
			if code != 1 || !strings.Contains(stderr.String(), test.want) {
				t.Fatalf("code=%d stderr=%q", code, stderr.String())
			}
		})
	}
}

func TestInitWritesConfigAndCreatesVerifiedAuditLog(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	dataDir := filepath.Join(t.TempDir(), "state")
	args := []string{"--config", configPath, "--data-dir", dataDir, "init"}

	code, stdout, stderr := invoke(t, args...)
	if code != 0 || stderr != "" || !strings.Contains(stdout, "Initialized Turnwire") {
		t.Fatalf("init: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	wantAudit := filepath.Join(dataDir, "audit")
	if cfg.AuditDir != wantAudit {
		t.Fatalf("AuditDir = %q, want %q", cfg.AuditDir, wantAudit)
	}
	if !filepath.IsAbs(cfg.AuditDir) {
		t.Fatalf("AuditDir = %q, want an absolute path", cfg.AuditDir)
	}
	if err := audit.Verify(wantAudit); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(configPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("config mode = %o", info.Mode().Perm())
		}
	}

	code, _, _ = invoke(t, args...)
	if code != 1 {
		t.Fatalf("second init code = %d, want 1", code)
	}
	forceArgs := append(append([]string{}, args...), "--force")
	code, _, stderr = invoke(t, forceArgs...)
	if code != 0 || stderr != "" {
		t.Fatalf("forced init: code=%d stderr=%q", code, stderr)
	}
}

func TestInitRejectsConfigPathAliasesAuditFile(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("secure audit storage is unavailable on this platform")
	}

	tests := []struct {
		name  string
		alias func(*testing.T, *initAliasFixture) string
	}{
		{
			name: "exact audit path",
			alias: func(_ *testing.T, fixture *initAliasFixture) string {
				return fixture.auditPath
			},
		},
		{
			name: "relative clean path",
			alias: func(t *testing.T, fixture *initAliasFixture) string {
				t.Chdir(fixture.root)
				separator := string(filepath.Separator)
				return "." + separator + "state" + separator + "audit" + separator + ".." + separator + "audit" + separator + audit.FileName
			},
		},
		{
			name: "hard link",
			alias: func(t *testing.T, fixture *initAliasFixture) string {
				alias := filepath.Join(fixture.root, "audit-hardlink.json")
				if err := os.Link(fixture.auditPath, alias); err != nil {
					t.Skipf("hard links unavailable: %v", err)
				}
				return alias
			},
		},
		{
			name: "symbolic link",
			alias: func(t *testing.T, fixture *initAliasFixture) string {
				alias := filepath.Join(fixture.root, "audit-symlink.json")
				if err := os.Symlink(fixture.auditPath, alias); err != nil {
					t.Skipf("symbolic links unavailable: %v", err)
				}
				return alias
			},
		},
		{
			name: "canonical parent alias",
			alias: func(t *testing.T, fixture *initAliasFixture) string {
				aliasRoot := filepath.Join(fixture.root, "state-alias")
				if err := os.Symlink(fixture.dataDir, aliasRoot); err != nil {
					t.Skipf("symbolic links unavailable: %v", err)
				}
				return filepath.Join(aliasRoot, "audit", audit.FileName)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newInitAliasFixture(t)
			alias := test.alias(t, fixture)
			fixture.assertRejected(t, alias, []string{"--config", alias})
		})
	}
}

func TestInitRejectsConfigPathThatSecureTraversalMapsToAuditEntry(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("secure audit storage is unavailable on this platform")
	}
	fixture := newInitAliasFixture(t)
	divergent := newDivergentTraversalFixture(t, fixture)

	args := []string{
		"--config", divergent.candidate,
		"--data-dir", fixture.dataDir,
		"init", "--force", "--model", "must-not-persist",
	}
	code, _, stderr := invoke(t, args...)
	if code != 1 || !strings.Contains(stderr, "config path must not name the audit log") {
		t.Fatalf("aliased init: code=%d stderr=%q", code, stderr)
	}
	if after, err := os.ReadFile(fixture.auditPath); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(after, fixture.auditBefore) {
		t.Fatal("audit history changed after rejected init")
	}
	if err := audit.Verify(fixture.auditDir); err != nil {
		t.Fatalf("verify preserved audit chain: %v", err)
	}
	if after, err := os.ReadFile(divergent.decoyPath); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(after, divergent.decoyBefore) {
		t.Fatal("decoy changed after rejected init")
	}
	if after, err := os.ReadFile(fixture.configPath); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(after, fixture.configBefore) {
		t.Fatal("existing config changed after rejected init")
	}
	auditInfo, err := os.Stat(fixture.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(fixture.auditInfo, auditInfo) {
		t.Fatal("audit file identity changed after rejected init")
	}
}

func TestWriteGuardedRejectsDivergentTraversalAuditAliasWithoutPreflight(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("secure audit storage is unavailable on this platform")
	}
	fixture := newInitAliasFixture(t)
	divergent := newDivergentTraversalFixture(t, fixture)
	log, err := audit.Open(fixture.auditDir)
	if err != nil {
		t.Fatal(err)
	}
	rejected := errors.New("guard rejected audit destination")
	guardCalled := false
	cfg := config.Default()
	cfg.AuditDir = fixture.auditDir
	cfg.Provider.Model = "must-not-persist"
	writeErr := config.WriteGuarded(divergent.candidate, cfg, true, func(parent *os.File, name string) error {
		guardCalled = true
		aliasesAudit, err := log.AliasesEntry(parent, name)
		if err != nil {
			return err
		}
		if aliasesAudit {
			return rejected
		}
		return nil
	})
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if !guardCalled {
		t.Fatal("destination guard was not called")
	}
	if !errors.Is(writeErr, rejected) {
		t.Fatalf("WriteGuarded error = %v, want audit rejection", writeErr)
	}
	if after, err := os.ReadFile(fixture.auditPath); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(after, fixture.auditBefore) {
		t.Fatal("audit history changed after guarded rejection")
	}
	if err := audit.Verify(fixture.auditDir); err != nil {
		t.Fatalf("verify preserved audit chain: %v", err)
	}
	if after, err := os.ReadFile(divergent.decoyPath); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(after, divergent.decoyBefore) {
		t.Fatal("decoy changed after guarded rejection")
	}
	if after, err := os.ReadFile(fixture.configPath); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(after, fixture.configBefore) {
		t.Fatal("existing config changed after guarded rejection")
	}
	auditInfo, err := os.Stat(fixture.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(fixture.auditInfo, auditInfo) {
		t.Fatal("audit file identity changed after guarded rejection")
	}
}

func TestInitRejectsDarwinCanonicalAuditAlias(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin path alias test")
	}
	fixture := newInitAliasFixture(t)
	alias, err := filepath.EvalSymlinks(fixture.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if alias == filepath.Clean(fixture.auditPath) {
		t.Skip("temporary directory has no canonical path alias")
	}
	fixture.assertRejected(t, alias, []string{"--config", alias})
}

func TestInitRejectsDefaultConfigAliasAuditFile(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("secure audit storage is unavailable on this platform")
	}
	fixture := newInitAliasFixture(t)
	if runtime.GOOS == "darwin" {
		t.Setenv("HOME", filepath.Join(fixture.root, "home"))
	} else {
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(fixture.root, "xdg-config"))
	}
	defaultPath := config.DefaultConfigPath()
	if defaultPath == "" {
		t.Fatal("default config path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(defaultPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fixture.auditPath, defaultPath); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	fixture.assertRejected(t, defaultPath, nil)
}

type initAliasFixture struct {
	root         string
	configPath   string
	dataDir      string
	auditDir     string
	auditPath    string
	configBefore []byte
	auditBefore  []byte
	auditInfo    os.FileInfo
}

type divergentTraversalFixture struct {
	candidate   string
	decoyPath   string
	decoyBefore []byte
}

func newDivergentTraversalFixture(t *testing.T, fixture *initAliasFixture) *divergentTraversalFixture {
	t.Helper()
	decoyRoot := filepath.Join(fixture.root, "decoy")
	decoyNested := filepath.Join(decoyRoot, "nested")
	decoyAuditDir := filepath.Join(decoyRoot, "audit")
	for _, directory := range []string{decoyNested, decoyAuditDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	decoyPath := filepath.Join(decoyAuditDir, audit.FileName)
	decoyBefore := []byte("decoy must remain intact\n")
	if err := os.WriteFile(decoyPath, decoyBefore, 0o600); err != nil {
		t.Fatal(err)
	}

	jump := filepath.Join(fixture.dataDir, "jump")
	if err := os.Symlink(decoyNested, jump); err != nil {
		t.Skipf("cannot create nested symlink: %v", err)
	}
	outer := filepath.Join(fixture.root, "outer")
	outerTarget := jump + string(filepath.Separator) + ".."
	if err := os.Symlink(outerTarget, outer); err != nil {
		t.Skipf("cannot create outer symlink: %v", err)
	}
	candidate := filepath.Join(outer, "audit", audit.FileName)
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		t.Fatal(err)
	}
	resolvedInfo, err := os.Stat(resolved)
	if err != nil {
		t.Fatal(err)
	}
	decoyInfo, err := os.Stat(decoyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(resolvedInfo, decoyInfo) {
		t.Fatalf("EvalSymlinks resolved %q away from the decoy", resolved)
	}
	if os.SameFile(resolvedInfo, fixture.auditInfo) {
		t.Fatal("test fixture does not exercise divergent path semantics")
	}
	return &divergentTraversalFixture{
		candidate:   candidate,
		decoyPath:   decoyPath,
		decoyBefore: decoyBefore,
	}
}

func newInitAliasFixture(t *testing.T) *initAliasFixture {
	t.Helper()
	root := t.TempDir()
	configPath := filepath.Join(root, "config.json")
	dataDir := filepath.Join(root, "state")
	code, _, stderr := invoke(t, "--config", configPath, "--data-dir", dataDir, "init")
	if code != 0 {
		t.Fatalf("initial init: code=%d stderr=%q", code, stderr)
	}
	auditDir := filepath.Join(dataDir, "audit")
	log, err := audit.Open(auditDir)
	if err != nil {
		t.Fatal(err)
	}
	appendAudit(t, log, audit.Event{
		EventID:        "history-event",
		ExchangeID:     "history-exchange",
		RequestID:      "history-request",
		ConversationID: "history-conversation",
		Type:           "history",
		Status:         "ok",
		Text:           "must remain intact",
	})
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(auditDir, audit.FileName)
	configBefore, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	auditBefore, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	auditInfo, err := os.Stat(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	return &initAliasFixture{
		root:         root,
		configPath:   configPath,
		dataDir:      dataDir,
		auditDir:     auditDir,
		auditPath:    auditPath,
		configBefore: configBefore,
		auditBefore:  auditBefore,
		auditInfo:    auditInfo,
	}
}

func (fixture *initAliasFixture) assertRejected(t *testing.T, alias string, configArgs []string) {
	t.Helper()
	aliasBefore, err := os.ReadFile(alias)
	if err != nil {
		t.Fatal(err)
	}
	args := append([]string{}, configArgs...)
	args = append(args, "--data-dir", fixture.dataDir, "init", "--force", "--model", "must-not-persist")
	code, _, stderr := invoke(t, args...)
	if code != 1 || !strings.Contains(stderr, "config path must not name the audit log") {
		t.Fatalf("aliased init: code=%d stderr=%q", code, stderr)
	}
	if after, err := os.ReadFile(fixture.auditPath); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(after, fixture.auditBefore) {
		t.Fatal("audit history changed after rejected init")
	}
	if err := audit.Verify(fixture.auditDir); err != nil {
		t.Fatalf("verify preserved audit chain: %v", err)
	}
	if after, err := os.ReadFile(fixture.configPath); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(after, fixture.configBefore) {
		t.Fatal("existing config changed after rejected init")
	}
	if after, err := os.ReadFile(alias); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(after, aliasBefore) {
		t.Fatal("aliased config entry changed after rejected init")
	}
	auditInfo, err := os.Stat(fixture.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	aliasInfo, err := os.Stat(alias)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(fixture.auditInfo, auditInfo) || !os.SameFile(auditInfo, aliasInfo) {
		t.Fatal("audit file identity changed after rejected init")
	}
}

func TestInitRemoteEndpointRequiresExplicitOptIn(t *testing.T) {
	root := t.TempDir()
	base := []string{
		"--config", filepath.Join(root, "config.json"),
		"--data-dir", filepath.Join(root, "state"),
		"init", "--endpoint", "https://example.com/v1/chat/completions",
	}
	code, _, stderr := invoke(t, base...)
	if code != 2 || !strings.Contains(stderr, "allow_remote") {
		t.Fatalf("without opt-in: code=%d stderr=%q", code, stderr)
	}
	code, _, stderr = invoke(t, append(base, "--allow-remote")...)
	if code != 0 || stderr != "" {
		t.Fatalf("with opt-in: code=%d stderr=%q", code, stderr)
	}
}

func TestInitOpenAIProviderPreset(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.json")
	code, _, stderr := invoke(t,
		"--config", configPath,
		"--data-dir", filepath.Join(root, "state"),
		"init", "--provider", "openai",
	)
	if code != 0 || stderr != "" {
		t.Fatalf("init: code=%d stderr=%q", code, stderr)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Provider.API != config.APIResponses || cfg.Provider.Endpoint != "https://api.openai.com/v1/responses" ||
		cfg.Provider.Model != "gpt-5.5" || cfg.Provider.APIKeyEnv != "OPENAI_API_KEY" || !cfg.Provider.AllowRemote {
		t.Fatalf("provider = %#v", cfg.Provider)
	}
}

func TestInitOpenAIProviderPresetAllowsGPT54(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.json")
	code, _, stderr := invoke(t,
		"--config", configPath,
		"--data-dir", filepath.Join(root, "state"),
		"init", "--provider", "openai", "--model", "gpt-5.4",
	)
	if code != 0 || stderr != "" {
		t.Fatalf("init: code=%d stderr=%q", code, stderr)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Provider.API != config.APIResponses || cfg.Provider.Model != "gpt-5.4" {
		t.Fatalf("provider = %#v", cfg.Provider)
	}
}

func TestInitOpenAIProviderPresetRejectsEndpointOverride(t *testing.T) {
	root := t.TempDir()
	code, _, stderr := invoke(t,
		"--config", filepath.Join(root, "config.json"),
		"--data-dir", filepath.Join(root, "state"),
		"init", "--provider", "openai", "--endpoint", "https://example.com/v1/responses",
	)
	if code != 2 || !strings.Contains(stderr, "cannot be combined") {
		t.Fatalf("init: code=%d stderr=%q", code, stderr)
	}
}

func TestForcedInitDoesNotReplaceConfigWhenAuditIsLocked(t *testing.T) {
	configPath, dataDir := initializeTestMailbox(t)
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	log, err := audit.Open(cfg.AuditDir)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	code, _, stderr := invoke(t,
		"--config", configPath,
		"--data-dir", dataDir,
		"init", "--force", "--model", "must-not-persist",
	)
	if code != 1 || !strings.Contains(stderr, "audit") {
		t.Fatalf("forced init: code=%d stderr=%q", code, stderr)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Provider.Model != cfg.Provider.Model {
		t.Fatalf("model changed after failed init: %q", loaded.Provider.Model)
	}
}

func TestRelativeDataDirectoryIsConsistentAcrossCommands(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	configPath := filepath.Join(root, "config.json")

	code, _, stderr := invoke(t, "--config", configPath, "--data-dir", "state", "init")
	if code != 0 || stderr != "" {
		t.Fatalf("init: code=%d stderr=%q", code, stderr)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "state", "audit")
	if cfg.AuditDir != want || !filepath.IsAbs(cfg.AuditDir) {
		t.Fatalf("AuditDir = %q, want absolute %q", cfg.AuditDir, want)
	}

	for _, command := range [][]string{
		{"doctor", "--json"},
		{"log", "verify", "--json"},
		{"log", "list", "--json"},
		{"serve"},
	} {
		args := []string{"--config", configPath, "--data-dir", "state"}
		code, _, stderr := invoke(t, append(args, command...)...)
		if code != 0 || stderr != "" {
			t.Fatalf("%v with relative data override: code=%d stderr=%q", command, code, stderr)
		}
	}

	// Without an override, commands continue to prefer the explicit absolute
	// audit path persisted in the configuration over any platform default.
	code, _, stderr = invoke(t, "--config", configPath, "doctor", "--json")
	if code != 0 || stderr != "" {
		t.Fatalf("doctor with configured audit path: code=%d stderr=%q", code, stderr)
	}
}

func TestCommandsRejectConfiguredAuditPathWithSymlinkDotDotSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("secure audit storage is unavailable on this platform")
	}

	root := t.TempDir()
	safeRoot := filepath.Join(root, "safe")
	decoyRoot := filepath.Join(root, "decoy")
	decoyNested := filepath.Join(decoyRoot, "nested")
	for _, dir := range []string{safeRoot, decoyNested} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(decoyNested, filepath.Join(safeRoot, "link")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	cleanAuditDir := filepath.Join(safeRoot, "audit")
	decoyAuditDir := filepath.Join(decoyRoot, "audit")
	for _, dir := range []string{cleanAuditDir, decoyAuditDir} {
		log, err := audit.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := log.Close(); err != nil {
			t.Fatal(err)
		}
	}

	separator := string(filepath.Separator)
	divergent := safeRoot + separator + "link" + separator + ".." + separator + "audit"
	if filepath.Clean(divergent) != cleanAuditDir {
		t.Fatalf("clean path = %q, want %q", filepath.Clean(divergent), cleanAuditDir)
	}
	rawInfo, err := os.Stat(divergent + separator + audit.FileName)
	if err != nil {
		t.Fatal(err)
	}
	decoyInfo, err := os.Stat(filepath.Join(decoyAuditDir, audit.FileName))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(rawInfo, decoyInfo) {
		t.Fatal("test path does not exercise divergent kernel symlink/.. semantics")
	}

	// The CLI wrappers retain the audit package's descriptor semantics even if
	// an invalid path reaches them outside the normal validated-config boundary.
	if err := os.Chmod(decoyAuditDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verifyAuditDir(divergent); err != nil {
		t.Fatalf("verifyAuditDir inspected a different target than audit traversal: %v", err)
	}
	if err := scanAuditDir(divergent, func(audit.Entry) error { return nil }); err != nil {
		t.Fatalf("scanAuditDir divergent path: %v", err)
	}

	cfg := config.Default()
	cfg.AuditDir = divergent
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "config.json")
	if err := os.WriteFile(configPath, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range [][]string{
		{"doctor", "--json"},
		{"log", "verify", "--json"},
		{"serve"},
	} {
		code, stdout, stderr := invoke(t, append([]string{"--config", configPath}, command...)...)
		if code != 1 || !strings.Contains(stdout+stderr, "config.audit_dir must be lexically clean") {
			t.Fatalf("%v: code=%d stdout=%q stderr=%q", command, code, stdout, stderr)
		}
	}
}

func TestCommandsUseDescriptorSemanticsWhenSymlinkTargetContainsDotDot(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("secure audit storage is unavailable on this platform")
	}

	root := t.TempDir()
	safeRoot := filepath.Join(root, "safe")
	safeAuditDir := filepath.Join(safeRoot, "audit")
	decoyRoot := filepath.Join(root, "decoy")
	decoyNested := filepath.Join(decoyRoot, "nested")
	decoyAuditDir := filepath.Join(decoyRoot, "audit")
	for _, dir := range []string{safeRoot, decoyNested, decoyAuditDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	safeLog, err := audit.Open(safeAuditDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := safeLog.Close(); err != nil {
		t.Fatal(err)
	}
	decoyPath := filepath.Join(decoyAuditDir, audit.FileName)
	decoyBefore := []byte("not a valid audit chain\n")
	if err := os.WriteFile(decoyPath, decoyBefore, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(decoyAuditDir, 0o755); err != nil {
		t.Fatal(err)
	}

	jump := filepath.Join(safeRoot, "jump")
	if err := os.Symlink(decoyNested, jump); err != nil {
		t.Skipf("cannot create nested symlink: %v", err)
	}
	outer := filepath.Join(root, "outer")
	separator := string(filepath.Separator)
	outerTarget := jump + separator + ".."
	if err := os.Symlink(outerTarget, outer); err != nil {
		t.Skipf("cannot create outer symlink: %v", err)
	}
	candidate := filepath.Join(outer, "audit")
	if filepath.Clean(candidate) != candidate {
		t.Fatalf("candidate path %q is not lexically clean", candidate)
	}
	rawInfo, err := os.Stat(filepath.Join(candidate, audit.FileName))
	if err != nil {
		t.Fatal(err)
	}
	decoyInfo, err := os.Stat(decoyPath)
	if err != nil {
		t.Fatal(err)
	}
	safeInfo, err := os.Stat(filepath.Join(safeAuditDir, audit.FileName))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(rawInfo, decoyInfo) || os.SameFile(rawInfo, safeInfo) {
		t.Fatal("test path does not exercise divergent symlink-target semantics")
	}

	cfg := config.Default()
	cfg.AuditDir = candidate
	configPath := filepath.Join(root, "config.json")
	if err := config.Write(configPath, cfg, false); err != nil {
		t.Fatal(err)
	}
	for _, command := range [][]string{
		{"doctor", "--json"},
		{"log", "verify", "--json"},
		{"log", "list", "--json"},
	} {
		code, stdout, stderr := invoke(t, append([]string{"--config", configPath}, command...)...)
		if code != 0 || stderr != "" {
			t.Fatalf("%v: code=%d stdout=%q stderr=%q", command, code, stdout, stderr)
		}
	}
	if after, err := os.ReadFile(decoyPath); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(after, decoyBefore) {
		t.Fatal("descriptor-based commands changed the raw-path decoy")
	}
}

func TestDoctorJSONAfterInit(t *testing.T) {
	configPath, dataDir := initializeTestMailbox(t)
	code, stdout, stderr := invoke(t, "--config", configPath, "--data-dir", dataDir, "doctor", "--json")
	if code != 0 || stderr != "" {
		t.Fatalf("doctor: code=%d stderr=%q", code, stderr)
	}
	var report doctorReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatal(err)
	}
	if !report.OK || len(report.Checks) != 3 {
		t.Fatalf("report = %#v", report)
	}
	for _, check := range report.Checks {
		if check.Status != "pass" {
			t.Fatalf("check = %#v", check)
		}
	}
}

func TestDoctorProbeIsGatedBySecurityPrerequisites(t *testing.T) {
	baseConfig := config.Default()
	baseConfig.AuditDir = filepath.Join(t.TempDir(), "audit")
	baseConfig.Provider.APIKeyEnv = "DOCTOR_SPY_API_KEY"

	tests := []struct {
		name       string
		loadErr    error
		verifyErr  error
		wantChecks int
	}{
		{name: "config security failure", loadErr: errors.New("config owner validation failed"), wantChecks: 1},
		{name: "unsupported audit platform", verifyErr: audit.ErrUnsupportedPlatform, wantChecks: 2},
		{name: "audit security failure", verifyErr: errors.New("audit permissions are too broad"), wantChecks: 2},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var verifyCalls, keyReads, probeCalls atomic.Int32
			deps := doctorDependencies{
				loadConfig: func(string) (config.Config, error) {
					return baseConfig, test.loadErr
				},
				verifyAudit: func(string, int64) error {
					verifyCalls.Add(1)
					return test.verifyErr
				},
				lookupEnv: func(string) (string, bool) {
					keyReads.Add(1)
					return "must-not-be-read", true
				},
				probe: func(context.Context, config.Config) error {
					probeCalls.Add(1)
					return nil
				},
			}
			var output bytes.Buffer
			err := runDoctorWithDependencies(
				context.Background(),
				[]string{"--probe", "--json"},
				options{},
				&output,
				deps,
			)
			if err == nil {
				t.Fatal("doctor unexpectedly passed failed prerequisites")
			}
			if got := keyReads.Load(); got != 0 {
				t.Fatalf("API key reads = %d, want 0", got)
			}
			if got := probeCalls.Load(); got != 0 {
				t.Fatalf("provider probes = %d, want 0", got)
			}
			if test.loadErr != nil && verifyCalls.Load() != 0 {
				t.Fatalf("audit verification ran after config failure")
			}
			var report doctorReport
			if err := json.Unmarshal(output.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if report.OK || len(report.Checks) != test.wantChecks {
				t.Fatalf("report = %#v", report)
			}
			if got := report.Checks[len(report.Checks)-1].Status; got != "fail" {
				t.Fatalf("final prerequisite status = %q, want fail", got)
			}
		})
	}
}

func TestDoctorProbeContactsProviderOnlyAfterGreenPrerequisites(t *testing.T) {
	configPath, dataDir := initializeTestMailbox(t)
	t.Setenv("TURNWIRE_DOCTOR_TEST_KEY", "doctor-secret")
	type observedRequest struct {
		authorization string
		body          string
	}
	requests := make(chan observedRequest, 2)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read failed", http.StatusInternalServerError)
			return
		}
		requests <- observedRequest{authorization: r.Header.Get("Authorization"), body: string(body)}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"OK"}}]}`)
	}))
	defer server.Close()

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Provider.Endpoint = server.URL + "/v1/chat/completions"
	cfg.Provider.APIKeyEnv = "TURNWIRE_DOCTOR_TEST_KEY"
	if err := config.Write(configPath, cfg, true); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := invoke(t, "--config", configPath, "--data-dir", dataDir, "doctor", "--probe", "--json")
	if code != 0 || stderr != "" {
		t.Fatalf("doctor: code=%d stderr=%q", code, stderr)
	}
	var report doctorReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatal(err)
	}
	if !report.OK || len(report.Checks) != 4 || report.Checks[3].Name != "provider" || report.Checks[3].Status != "pass" {
		t.Fatalf("report = %#v", report)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("provider calls = %d, want 1", got)
	}
	select {
	case request := <-requests:
		if request.authorization != "Bearer doctor-secret" {
			t.Fatalf("authorization = %q", request.authorization)
		}
		if !strings.Contains(request.body, probeText) {
			t.Fatalf("probe body = %q", request.body)
		}
	default:
		t.Fatal("provider did not observe probe")
	}
	entries, err := audit.ReadAll(filepath.Join(dataDir, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("doctor mutated audit log: %#v", entries)
	}
}

func TestDoctorProbeDoesNotContactProviderWithMissingCredential(t *testing.T) {
	cfg := config.Default()
	cfg.AuditDir = filepath.Join(t.TempDir(), "audit")
	cfg.Provider.APIKeyEnv = "MISSING_DOCTOR_KEY"
	var keyReads, probeCalls atomic.Int32
	deps := doctorDependencies{
		loadConfig:  func(string) (config.Config, error) { return cfg, nil },
		verifyAudit: func(string, int64) error { return nil },
		lookupEnv: func(string) (string, bool) {
			keyReads.Add(1)
			return "", false
		},
		probe: func(context.Context, config.Config) error {
			probeCalls.Add(1)
			return nil
		},
	}
	var output bytes.Buffer
	err := runDoctorWithDependencies(
		context.Background(), []string{"--probe", "--json"}, options{}, &output, deps,
	)
	if err == nil {
		t.Fatal("doctor unexpectedly passed with missing credentials")
	}
	if keyReads.Load() != 1 || probeCalls.Load() != 0 {
		t.Fatalf("key reads=%d provider probes=%d, want 1 and 0", keyReads.Load(), probeCalls.Load())
	}
	var report doctorReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.OK || len(report.Checks) != 3 || report.Checks[2].Name != "credentials" || report.Checks[2].Status != "fail" {
		t.Fatalf("report = %#v", report)
	}
}

func TestLogCommandsPreserveJSONAndQuoteHumanText(t *testing.T) {
	configPath, dataDir := initializeTestMailbox(t)
	auditDir := filepath.Join(dataDir, "audit")
	log, err := audit.Open(auditDir)
	if err != nil {
		t.Fatal(err)
	}
	input := "hello\n\x1b[31m"
	output := "reply\r\nworld 🌍"
	appendAudit(t, log, audit.Event{
		EventID: "event-1", ExchangeID: "exchange-1", RequestID: "request-1",
		ConversationID: "conversation-1", Type: "request_received", Status: "accepted", Text: input,
	})
	appendAudit(t, log, audit.Event{
		EventID: "event-2", ExchangeID: "exchange-1", RequestID: "request-1",
		ConversationID: "conversation-1", Type: "reply_committed", Status: "succeeded", Text: output,
	})
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	global := []string{"--config", configPath, "--data-dir", dataDir, "log"}
	code, stdout, stderr := invoke(t, append(global, "list", "--conversation", "conversation-1", "--json")...)
	if code != 0 || stderr != "" {
		t.Fatalf("list: code=%d stderr=%q", code, stderr)
	}
	var records []exchangeRecord
	if err := json.Unmarshal([]byte(stdout), &records); err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Input != input || records[0].Output != output {
		t.Fatalf("records = %#v", records)
	}

	code, stdout, stderr = invoke(t, append(global, "show", "exchange-1", "--json")...)
	if code != 0 || stderr != "" {
		t.Fatalf("show JSON: code=%d stderr=%q", code, stderr)
	}
	var record exchangeRecord
	if err := json.Unmarshal([]byte(stdout), &record); err != nil {
		t.Fatal(err)
	}
	if record.Input != input || record.Output != output {
		t.Fatalf("record = %#v", record)
	}

	code, stdout, stderr = invoke(t, append(global, "show", "exchange-1")...)
	if code != 0 || stderr != "" {
		t.Fatalf("show human: code=%d stderr=%q", code, stderr)
	}
	if strings.ContainsRune(stdout, '\x1b') || !strings.Contains(stdout, `\n`) || !strings.Contains(stdout, `\x1b`) {
		t.Fatalf("human output did not safely quote controls: %q", stdout)
	}

	code, stdout, stderr = invoke(t, append(global, "verify", "--json")...)
	if code != 0 || stderr != "" || !strings.Contains(stdout, `"ok":true`) {
		t.Fatalf("verify: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestLogListJSONBudgetUsesFinalLimitWindow(t *testing.T) {
	configPath, dataDir := initializeTestMailbox(t)
	auditDir := filepath.Join(dataDir, "audit")
	log, err := audit.Open(auditDir)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("x", 9<<20)
	for i := 0; i < 2; i++ {
		id := "large-exchange-" + strconv.Itoa(i)
		appendAudit(t, log, audit.Event{
			EventID: "large-event-" + strconv.Itoa(i), ExchangeID: id, RequestID: "request-" + id,
			ConversationID: "large-conversation", Type: "request_received", Status: "accepted", Text: body,
		})
	}
	for i := 0; i < 2; i++ {
		id := "tail-exchange-" + strconv.Itoa(i)
		appendAudit(t, log, audit.Event{
			EventID: "tail-event-" + strconv.Itoa(i), ExchangeID: id, RequestID: "request-" + id,
			ConversationID: "large-conversation", Type: "request_received", Status: "accepted", Text: "tiny",
		})
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := invoke(
		t,
		"--config", configPath,
		"--data-dir", dataDir,
		"log", "list", "--limit", "2", "--json",
	)
	if code != 0 || stderr != "" {
		t.Fatalf("bounded tail: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	var records []exchangeRecord
	if err := json.Unmarshal([]byte(stdout), &records); err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].ExchangeID != "tail-exchange-1" || records[1].ExchangeID != "tail-exchange-0" {
		t.Fatalf("bounded tail records = %#v", records)
	}

	code, stdout, stderr = invoke(
		t,
		"--config", configPath,
		"--data-dir", dataDir,
		"log", "list", "--limit", "1000", "--json",
	)
	if code != 1 || stdout != "" || !strings.Contains(stderr, "16 MiB in-memory record limit") {
		t.Fatalf("budget failure: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if err := audit.Verify(auditDir); err != nil {
		t.Fatalf("verify after bounded query: %v", err)
	}
}

func TestLogValidationAndMissingExchangeExitCodes(t *testing.T) {
	configPath, dataDir := initializeTestMailbox(t)
	base := []string{"--config", configPath, "--data-dir", dataDir, "log"}
	code, _, stderr := invoke(t, append(base, "list", "--limit", "0")...)
	if code != 2 || !strings.Contains(stderr, "--limit") {
		t.Fatalf("bad limit: code=%d stderr=%q", code, stderr)
	}
	code, _, stderr = invoke(t, append(base, "show", "missing")...)
	if code != 1 || !strings.Contains(stderr, "was not found") {
		t.Fatalf("missing show: code=%d stderr=%q", code, stderr)
	}
}

func TestLogCommandsPropagateWriteFailures(t *testing.T) {
	opts, exchangeID := initializeLogOutputFixture(t)
	writeFailure := errors.New("test log output failure")
	tests := []struct {
		name             string
		successfulWrites int
		run              func(io.Writer) error
	}{
		{
			name: "list no records",
			run: func(w io.Writer) error {
				return runLogList([]string{"--conversation", "missing"}, opts, w)
			},
		},
		{
			name: "list header",
			run:  func(w io.Writer) error { return runLogList(nil, opts, w) },
		},
		{
			name:             "list row",
			successfulWrites: 1,
			run:              func(w io.Writer) error { return runLogList(nil, opts, w) },
		},
		{
			name:             "show final line",
			successfulWrites: 7,
			run:              func(w io.Writer) error { return runLogShow([]string{exchangeID}, opts, w) },
		},
		{
			name: "show JSON",
			run:  func(w io.Writer) error { return runLogShow([]string{exchangeID, "--json"}, opts, w) },
		},
		{
			name: "verify success",
			run:  func(w io.Writer) error { return runLogVerify(nil, opts, w) },
		},
		{
			name: "verify JSON",
			run:  func(w io.Writer) error { return runLogVerify([]string{"--json"}, opts, w) },
		},
		{
			name: "log help",
			run:  func(w io.Writer) error { return runLog(nil, opts, w) },
		},
		{
			name: "top-level log help",
			run:  func(w io.Writer) error { return runHelp([]string{"log"}, w) },
		},
		{
			name: "show help",
			run:  func(w io.Writer) error { return runLogShow([]string{"--help"}, opts, w) },
		},
		{
			name: "list flag help",
			run:  func(w io.Writer) error { return runLogList([]string{"--help"}, opts, w) },
		},
		{
			name: "verify flag help",
			run:  func(w io.Writer) error { return runLogVerify([]string{"--help"}, opts, w) },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			writer := &failAfterWriter{remaining: test.successfulWrites, err: writeFailure}
			if err := test.run(writer); !errors.Is(err, writeFailure) {
				t.Fatalf("output error = %v, want %v", err, writeFailure)
			}
		})
	}
}

func TestLogCommandsRejectShortWritesAndFailExit(t *testing.T) {
	opts, exchangeID := initializeLogOutputFixture(t)
	direct := []struct {
		name string
		run  func(io.Writer) error
	}{
		{name: "list", run: func(w io.Writer) error { return runLogList(nil, opts, w) }},
		{name: "show", run: func(w io.Writer) error { return runLogShow([]string{exchangeID}, opts, w) }},
		{name: "show JSON", run: func(w io.Writer) error { return runLogShow([]string{exchangeID, "--json"}, opts, w) }},
		{name: "verify", run: func(w io.Writer) error { return runLogVerify(nil, opts, w) }},
		{name: "verify JSON", run: func(w io.Writer) error { return runLogVerify([]string{"--json"}, opts, w) }},
		{name: "help", run: func(w io.Writer) error { return runLog(nil, opts, w) }},
	}
	for _, test := range direct {
		t.Run(test.name+" error", func(t *testing.T) {
			if err := test.run(shortOutputWriter{}); !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("short-write error = %v, want %v", err, io.ErrShortWrite)
			}
		})
	}

	commands := [][]string{
		{"--config", opts.configPath, "--data-dir", opts.dataDir, "log", "list"},
		{"--config", opts.configPath, "--data-dir", opts.dataDir, "log", "show", exchangeID},
		{"--config", opts.configPath, "--data-dir", opts.dataDir, "log", "show", exchangeID, "--json"},
		{"--config", opts.configPath, "--data-dir", opts.dataDir, "log", "verify"},
		{"--config", opts.configPath, "--data-dir", opts.dataDir, "log", "verify", "--json"},
	}
	for _, command := range commands {
		var stderr bytes.Buffer
		code := Run(context.Background(), command, strings.NewReader(""), shortOutputWriter{}, &stderr)
		if code != 1 || !strings.Contains(stderr.String(), io.ErrShortWrite.Error()) {
			t.Fatalf("%v: code=%d stderr=%q", command, code, stderr.String())
		}
	}
}

type failAfterWriter struct {
	remaining int
	err       error
}

func (w *failAfterWriter) Write(data []byte) (int, error) {
	if w.remaining == 0 {
		return 0, w.err
	}
	w.remaining--
	return len(data), nil
}

type shortOutputWriter struct{}

func (shortOutputWriter) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	return len(data) - 1, nil
}

func TestExchangeListScannerHandlesInterleavingAndFilter(t *testing.T) {
	scanner := newExchangeListScanner("keep", 1, true)
	entries := []audit.Entry{
		{Seq: 1, ExchangeID: "old", RequestID: "request-old", ConversationID: "keep", Type: "request_received", Timestamp: "created-old", Text: "old input", TextSHA256: "input-old", EntryHash: "head-1"},
		{Seq: 2, ExchangeID: "new", RequestID: "request-new", ConversationID: "keep", Type: "request_received", Timestamp: "created-new", Text: "new input", TextSHA256: "input-new", EntryHash: "head-2"},
		{Seq: 3, ExchangeID: "other", RequestID: "request-other", ConversationID: "skip", Type: "request_received", Timestamp: "created-other", Text: "other input", TextSHA256: "input-other", EntryHash: "head-3"},
		{Seq: 4, ExchangeID: "new", RequestID: "request-new", ConversationID: "keep", Type: "reply_committed", Timestamp: "completed-new", Text: "new output", TextSHA256: "output-new", EntryHash: "head-4"},
		{Seq: 5, ExchangeID: "old", RequestID: "request-old", ConversationID: "keep", Type: "run_failed", Timestamp: "completed-old", ErrorCode: "timeout", EntryHash: "head-5"},
		{Seq: 6, ExchangeID: "other", RequestID: "request-other", ConversationID: "skip", Type: "reply_committed", Timestamp: "completed-other", Text: "other output", TextSHA256: "output-other", EntryHash: "head-6"},
	}
	for _, entry := range entries {
		if err := scanner.consume(entry); err != nil {
			t.Fatal(err)
		}
	}
	records, err := scanner.records()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %#v", records)
	}
	record := records[0]
	if record.ExchangeID != "new" || record.Status != "succeeded" || record.Output != "new output" || record.LastSequence != 4 {
		t.Fatalf("record = %#v", record)
	}
}

func TestExchangeListScannerRetentionIsBounded(t *testing.T) {
	const (
		limit = 3
		total = 256
	)
	scanner := newExchangeListScanner("", limit, true)
	large := strings.Repeat("x", 64<<10)
	for i := 0; i < total; i++ {
		id := "exchange-" + strconv.Itoa(i)
		if err := scanner.consume(audit.Entry{
			Seq: uint64(i*2 + 1), ExchangeID: id, RequestID: "request-" + id,
			ConversationID: "conversation", Type: "request_received", Text: large + id,
		}); err != nil {
			t.Fatal(err)
		}
		if err := scanner.consume(audit.Entry{
			Seq: uint64(i*2 + 2), ExchangeID: id, RequestID: "request-" + id,
			ConversationID: "conversation", Type: "reply_committed", Text: large + "reply-" + id,
		}); err != nil {
			t.Fatal(err)
		}
		if scanner.count > limit || len(scanner.retainedByID) > limit {
			t.Fatalf("retained count grew past limit: count=%d map=%d", scanner.count, len(scanner.retainedByID))
		}
	}
	records, err := scanner.records()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != limit || records[0].ExchangeID != "exchange-255" || records[2].ExchangeID != "exchange-253" {
		t.Fatalf("records = %#v", records)
	}
}

func TestExchangeListScannerHumanModeDoesNotRetainBodies(t *testing.T) {
	const (
		limit = 1000
		total = 128
	)
	scanner := newExchangeListScanner("", limit, false)
	large := strings.Repeat("x", 1<<20)
	for i := 0; i < total; i++ {
		id := "exchange-" + strconv.Itoa(i)
		if err := scanner.consume(audit.Entry{
			Seq: uint64(i*2 + 1), ExchangeID: id, RequestID: "request-" + id,
			ConversationID: "conversation", Type: "request_received", Timestamp: "created", Text: large,
		}); err != nil {
			t.Fatal(err)
		}
		if err := scanner.consume(audit.Entry{
			Seq: uint64(i*2 + 2), ExchangeID: id, RequestID: "request-" + id,
			ConversationID: "conversation", Type: "reply_committed", Timestamp: "completed", Text: large,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if scanner.count != total || scanner.retainedBytes >= 1<<20 {
		t.Fatalf("human retention: count=%d bytes=%d", scanner.count, scanner.retainedBytes)
	}
	records, err := scanner.records()
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if record.Input != "" || record.Output != "" {
			t.Fatal("human list retained a message body")
		}
	}
}

func TestExchangeListScannerJSONRetentionBudget(t *testing.T) {
	scanner := newExchangeListScanner("", 1000, true)
	scanner.maxRetainedBytes = 5 << 20
	large := strings.Repeat("x", 1<<20)
	for i := 0; i < 10; i++ {
		id := "exchange-" + strconv.Itoa(i)
		body := large + id
		if err := scanner.consume(audit.Entry{
			Seq: uint64(i*2 + 1), ExchangeID: id, RequestID: "request-" + id,
			ConversationID: "conversation", Type: "request_received", Timestamp: "created", Text: body,
		}); err != nil {
			t.Fatal(err)
		}
		if scanner.retainedBytes > scanner.maxRetainedBytes {
			t.Fatalf("request retained %d bytes past %d-byte budget", scanner.retainedBytes, scanner.maxRetainedBytes)
		}
		if err := scanner.consume(audit.Entry{
			Seq: uint64(i*2 + 2), ExchangeID: id, RequestID: "request-" + id,
			ConversationID: "conversation", Type: "reply_committed", Timestamp: "completed", Text: body,
		}); err != nil {
			t.Fatal(err)
		}
		if scanner.retainedBytes > scanner.maxRetainedBytes {
			t.Fatalf("reply retained %d bytes past %d-byte budget", scanner.retainedBytes, scanner.maxRetainedBytes)
		}
	}
	if _, err := scanner.records(); !errors.Is(err, errLogListTooLarge) {
		t.Fatalf("retention error = %v, want %v", err, errLogListTooLarge)
	}
	if scanner.retainedBytes > scanner.maxRetainedBytes {
		t.Fatalf("retained %d bytes past %d-byte budget", scanner.retainedBytes, scanner.maxRetainedBytes)
	}
	if scanner.count == 0 || scanner.count >= 10 {
		t.Fatalf("retained count = %d, want bounded partial set", scanner.count)
	}
}

func TestExchangeListScannerAllowsBudgetEvictedHistoricalPrefix(t *testing.T) {
	scanner := newExchangeListScanner("", 2, true)
	scanner.maxRetainedBytes = 1 << 20
	large := strings.Repeat("x", 2<<20)
	entries := []audit.Entry{
		{ExchangeID: "large-1", RequestID: "request-large-1", ConversationID: "conversation", Type: "request_received", Text: large},
		{ExchangeID: "large-2", RequestID: "request-large-2", ConversationID: "conversation", Type: "request_received", Text: large},
		{ExchangeID: "tail-1", RequestID: "request-tail-1", ConversationID: "conversation", Type: "request_received", Text: "tiny-1"},
		{ExchangeID: "tail-2", RequestID: "request-tail-2", ConversationID: "conversation", Type: "request_received", Text: "tiny-2"},
	}
	for _, entry := range entries {
		if err := scanner.consume(entry); err != nil {
			t.Fatal(err)
		}
		if scanner.retainedBytes > scanner.maxRetainedBytes {
			t.Fatalf("retained %d bytes past %d-byte budget", scanner.retainedBytes, scanner.maxRetainedBytes)
		}
	}
	records, err := scanner.records()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].ExchangeID != "tail-2" || records[1].ExchangeID != "tail-1" {
		t.Fatalf("records = %#v", records)
	}
	if scanner.maxBudgetEvictedOrdinal != 2 || scanner.totalRequests != 4 {
		t.Fatalf("ordinals: evicted=%d total=%d", scanner.maxBudgetEvictedOrdinal, scanner.totalRequests)
	}
}

func TestExchangeListScannerOversizedUpdateEvictsThroughCurrentRecord(t *testing.T) {
	scanner := newExchangeListScanner("", 2, true)
	scanner.maxRetainedBytes = 1 << 20
	for i := 1; i <= 2; i++ {
		id := "exchange-" + strconv.Itoa(i)
		if err := scanner.consume(audit.Entry{
			ExchangeID: id, RequestID: "request-" + id, ConversationID: "conversation",
			Type: "request_received", Text: "small",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := scanner.consume(audit.Entry{
		ExchangeID: "exchange-2", RequestID: "request-exchange-2", ConversationID: "conversation",
		Type: "reply_committed", Text: strings.Repeat("x", 2<<20),
	}); err != nil {
		t.Fatal(err)
	}
	if scanner.count != 0 || len(scanner.retainedByID) != 0 || scanner.retainedBytes != 0 {
		t.Fatalf("oversized update state: count=%d map=%d bytes=%d", scanner.count, len(scanner.retainedByID), scanner.retainedBytes)
	}
	if scanner.maxBudgetEvictedOrdinal != 2 {
		t.Fatalf("max budget-evicted ordinal = %d, want 2", scanner.maxBudgetEvictedOrdinal)
	}
	if _, err := scanner.records(); !errors.Is(err, errLogListTooLarge) {
		t.Fatalf("records error = %v, want %v", err, errLogListTooLarge)
	}
}

func TestExchangeListScannerHumanMetadataUsesRetentionBudget(t *testing.T) {
	scanner := newExchangeListScanner("", 1000, false)
	scanner.maxRetainedBytes = 1024
	if err := scanner.consume(audit.Entry{
		ExchangeID: strings.Repeat("x", 2048), ConversationID: "conversation",
		Type: "request_received", Timestamp: "created",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := scanner.records(); !errors.Is(err, errLogListTooLarge) {
		t.Fatalf("human retention error = %v, want %v", err, errLogListTooLarge)
	}
	if scanner.count != 0 || scanner.retainedBytes != 0 {
		t.Fatalf("rejected human record changed state: count=%d bytes=%d", scanner.count, scanner.retainedBytes)
	}
}

func TestWriteExchangeRecordsJSONStreamsIndividualRecords(t *testing.T) {
	body := strings.Repeat("x", 1<<20)
	records := make([]exchangeRecord, 4)
	for i := range records {
		records[i] = exchangeRecord{ExchangeID: "exchange-" + strconv.Itoa(i), Input: body}
	}
	output := &maxChunkBuffer{maximum: 2 << 20}
	if err := writeExchangeRecordsJSON(output, records); err != nil {
		t.Fatal(err)
	}
	var decoded []exchangeRecord
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("decode streamed JSON: %v", err)
	}
	if len(decoded) != len(records) || decoded[3].Input != body {
		t.Fatalf("decoded records = %#v", decoded)
	}
}

type maxChunkBuffer struct {
	bytes.Buffer
	maximum int
}

func (w *maxChunkBuffer) Write(data []byte) (int, error) {
	if len(data) > w.maximum {
		return 0, errors.New("write chunk exceeded test maximum")
	}
	return w.Buffer.Write(data)
}

func TestLogQueriesRejectTamperedTail(t *testing.T) {
	configPath, dataDir := initializeTestMailbox(t)
	auditDir := filepath.Join(dataDir, "audit")
	log, err := audit.Open(auditDir)
	if err != nil {
		t.Fatal(err)
	}
	appendAudit(t, log, audit.Event{
		EventID: "event-request", ExchangeID: "exchange", RequestID: "request",
		ConversationID: "conversation", Type: "request_received", Status: "accepted", Text: "hello",
	})
	appendAudit(t, log, audit.Event{
		EventID: "event-reply", ExchangeID: "exchange", RequestID: "request",
		ConversationID: "conversation", Type: "reply_committed", Status: "succeeded", Text: "reply",
	})
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(auditDir, audit.FileName)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(contents), `"text":"reply"`, `"text":"other"`, 1)
	if tampered == string(contents) {
		t.Fatal("reply text was not found in audit log")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}

	base := []string{"--config", configPath, "--data-dir", dataDir, "log"}
	for _, command := range [][]string{{"list", "--json"}, {"show", "exchange", "--json"}} {
		code, stdout, stderr := invoke(t, append(base, command...)...)
		if code != 1 || stdout != "" || !strings.Contains(stderr, "text hash") {
			t.Fatalf("%v: code=%d stdout=%q stderr=%q", command, code, stdout, stderr)
		}
	}
}

func TestServeRefusesCharacterDeviceStdin(t *testing.T) {
	device, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	if !terminalReader(device) {
		t.Skip("null device is not reported as a character device")
	}
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"serve"}, device, &stdout, &stderr)
	if code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "expects an MCP client") {
		t.Fatalf("serve: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestServeSanitizesTransportErrors(t *testing.T) {
	configPath, dataDir := initializeTestMailbox(t)
	const sentinel = "\x1b[31mPRIVATE-TRANSPORT-DETAIL\nsecond-line"
	var stdout, stderr bytes.Buffer
	code := Run(
		context.Background(),
		[]string{"--config", configPath, "--data-dir", dataDir, "serve"},
		errorReader{err: errors.New(sentinel)},
		&stdout,
		&stderr,
	)
	if code != 1 {
		t.Fatalf("serve code = %d, want 1; stderr=%q", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("serve stdout = %q, want empty", stdout.String())
	}
	if got := stderr.String(); got != "error: MCP transport failed\n" {
		t.Fatalf("serve stderr = %q, want fixed transport error", got)
	}
	if strings.Contains(stderr.String(), sentinel) || strings.ContainsRune(stderr.String(), '\x1b') {
		t.Fatalf("serve exposed transport sentinel: %q", stderr.String())
	}
}

func TestVerifyWritableAuditDirAllowsEmptyLog(t *testing.T) {
	auditDir := filepath.Join(t.TempDir(), "audit")
	log, err := audit.Open(auditDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if err := verifyWritableAuditDir(auditDir, 1); err != nil {
		t.Fatalf("verifyWritableAuditDir(empty): %v", err)
	}
}

func TestDoctorRefusesFullAuditQuotaButLogVerifyAllowsInspection(t *testing.T) {
	configPath, dataDir := initializeTestMailbox(t)
	auditDir := filepath.Join(dataDir, "audit")
	log, err := audit.Open(auditDir)
	if err != nil {
		t.Fatal(err)
	}
	appendAudit(t, log, audit.Event{
		EventID: "doctor-quota-seed", ExchangeID: "doctor-quota-exchange", RequestID: "doctor-quota-request",
		ConversationID: "doctor-quota-conversation", Type: "run_failed", Status: "failed",
	})
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(auditDir, audit.FileName))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Limits.MaxAuditBytes = info.Size()
	if err := config.Write(configPath, cfg, true); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := invoke(t, "--config", configPath, "--data-dir", dataDir, "doctor", "--json")
	if code != 1 || stderr != "" {
		t.Fatalf("doctor: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	var report doctorReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatal(err)
	}
	if report.OK || len(report.Checks) != 2 || report.Checks[1].Name != "audit" ||
		report.Checks[1].Status != "fail" || !strings.Contains(report.Checks[1].Message, audit.ErrQuotaExceeded.Error()) {
		t.Fatalf("doctor report = %#v", report)
	}

	code, stdout, stderr = invoke(t, "--config", configPath, "--data-dir", dataDir, "log", "verify", "--json")
	if code != 0 || stderr != "" {
		t.Fatalf("log verify: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	var verification struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal([]byte(stdout), &verification); err != nil {
		t.Fatal(err)
	}
	if !verification.OK {
		t.Fatalf("log verification = %#v", verification)
	}
}

func TestServeRefusesFullAuditQuotaBeforeConstructingResponder(t *testing.T) {
	configPath, dataDir := initializeTestMailbox(t)
	auditDir := filepath.Join(dataDir, "audit")
	log, err := audit.Open(auditDir)
	if err != nil {
		t.Fatal(err)
	}
	appendAudit(t, log, audit.Event{
		EventID: "quota-seed", ExchangeID: "quota-exchange", RequestID: "quota-request",
		ConversationID: "quota-conversation", Type: "run_failed", Status: "failed",
	})
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(auditDir, audit.FileName))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Limits.MaxAuditBytes = info.Size()
	if err := config.Write(configPath, cfg, true); err != nil {
		t.Fatal(err)
	}

	constructed := false
	err = runServeWithResponder(
		context.Background(),
		nil,
		options{configPath: configPath, dataDir: dataDir},
		strings.NewReader(""),
		io.Discard,
		io.Discard,
		func(responder.HTTPConfig) (responder.Responder, error) {
			constructed = true
			return nil, nil
		},
	)
	if !errors.Is(err, audit.ErrQuotaExceeded) {
		t.Fatalf("runServeWithResponder error = %v, want ErrQuotaExceeded", err)
	}
	if constructed {
		t.Fatal("responder was constructed after the audit quota was exhausted")
	}
	if err := audit.Verify(auditDir); err != nil {
		t.Fatalf("Verify after refused serve: %v", err)
	}
}

func TestServeTeardownPromptlyCancelsAndDrainsMailbox(t *testing.T) {
	for _, mode := range []string{"context", "eof"} {
		t.Run(mode, func(t *testing.T) {
			configPath, dataDir := initializeTestMailbox(t)
			model := newTeardownTestResponder()
			stdin, input := io.Pipe()
			ctx, cancel := context.WithCancel(context.Background())
			var stdout, stderr bytes.Buffer
			runDone := make(chan error, 1)
			go func() {
				runDone <- runServeWithResponder(
					ctx,
					nil,
					options{configPath: configPath, dataDir: dataDir},
					stdin,
					&stdout,
					&stderr,
					func(responder.HTTPConfig) (responder.Responder, error) { return model, nil },
				)
			}()
			t.Cleanup(func() {
				model.abortCall()
				cancel()
				_ = input.Close()
				_ = stdin.Close()
			})

			const requests = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"teardown-test","version":"1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"talk","arguments":{"text":"cancel me","request_id":"teardown-request","conversation_id":"conversation"}}}
`
			writeDone := make(chan error, 1)
			go func() {
				_, err := io.WriteString(input, requests)
				writeDone <- err
			}()
			select {
			case err := <-writeDone:
				if err != nil {
					t.Fatalf("write MCP requests: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("MCP requests were not consumed")
			}
			select {
			case <-model.started:
			case <-time.After(time.Second):
				t.Fatal("talk request did not reach responder")
			}

			startedTeardown := time.Now()
			if mode == "context" {
				cancel()
			} else if err := input.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-model.canceled:
				if elapsed := time.Since(startedTeardown); elapsed > 500*time.Millisecond {
					t.Fatalf("provider cancellation took %s", elapsed)
				}
			case <-time.After(time.Second):
				t.Fatal("MCP teardown did not cancel provider")
			}
			select {
			case err := <-runDone:
				t.Fatalf("serve returned before detached worker drained: %v", err)
			case <-time.After(20 * time.Millisecond):
			}

			model.unblock()
			select {
			case err := <-runDone:
				if err != nil {
					t.Fatalf("serve returned error: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("serve did not return after mailbox drain")
			}
			reopened, err := audit.Open(filepath.Join(dataDir, "audit"))
			if err != nil {
				t.Fatalf("reopen drained audit log: %v", err)
			}
			entries, err := reopened.ReadAll()
			if closeErr := reopened.Close(); err == nil {
				err = closeErr
			}
			if err != nil {
				t.Fatalf("read drained audit log: %v", err)
			}
			if len(entries) != 2 || entries[0].Type != "request_received" || entries[1].Type != "run_failed" || entries[1].ErrorCode != "canceled" {
				t.Fatalf("teardown audit entries = %#v", entries)
			}
		})
	}
}

type teardownTestResponder struct {
	started      chan struct{}
	canceled     chan struct{}
	release      chan struct{}
	abort        chan struct{}
	startedOnce  sync.Once
	canceledOnce sync.Once
	releaseOnce  sync.Once
	abortOnce    sync.Once
}

func newTeardownTestResponder() *teardownTestResponder {
	return &teardownTestResponder{
		started:  make(chan struct{}),
		canceled: make(chan struct{}),
		release:  make(chan struct{}),
		abort:    make(chan struct{}),
	}
}

func (r *teardownTestResponder) Respond(ctx context.Context, _ string) (string, error) {
	r.startedOnce.Do(func() { close(r.started) })
	select {
	case <-ctx.Done():
		r.canceledOnce.Do(func() { close(r.canceled) })
	case <-r.abort:
		return "", errors.New("test responder aborted")
	}
	select {
	case <-r.release:
		return "", ctx.Err()
	case <-r.abort:
		return "", errors.New("test responder aborted")
	}
}

func (r *teardownTestResponder) unblock() {
	r.releaseOnce.Do(func() { close(r.release) })
}

func (r *teardownTestResponder) abortCall() {
	r.abortOnce.Do(func() { close(r.abort) })
}

type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

func initializeLogOutputFixture(t *testing.T) (options, string) {
	t.Helper()
	configPath, dataDir := initializeTestMailbox(t)
	log, err := audit.Open(filepath.Join(dataDir, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	const exchangeID = "write-failure-exchange"
	appendAudit(t, log, audit.Event{
		EventID: "write-failure-request-event", ExchangeID: exchangeID, RequestID: "write-failure-request",
		ConversationID: "write-failure-conversation", Type: "request_received", Status: "accepted", Text: "input",
	})
	appendAudit(t, log, audit.Event{
		EventID: "write-failure-reply-event", ExchangeID: exchangeID, RequestID: "write-failure-request",
		ConversationID: "write-failure-conversation", Type: "reply_committed", Status: "succeeded", Text: "output",
	})
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	return options{configPath: configPath, dataDir: dataDir}, exchangeID
}

func initializeTestMailbox(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	configPath := filepath.Join(root, "config.json")
	dataDir := filepath.Join(root, "state")
	code, _, stderr := invoke(t, "--config", configPath, "--data-dir", dataDir, "init")
	if code != 0 {
		t.Fatalf("init: code=%d stderr=%q", code, stderr)
	}
	return configPath, dataDir
}

func appendAudit(t *testing.T, log *audit.Log, event audit.Event) {
	t.Helper()
	if _, err := log.Append(event); err != nil {
		t.Fatal(err)
	}
}

func invoke(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), args, strings.NewReader(""), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}
