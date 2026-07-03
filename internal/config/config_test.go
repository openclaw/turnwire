package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/openclaw/turnwire/internal/audit"
	"github.com/openclaw/turnwire/internal/owneronly"
)

func TestLoadMissingDefaultUsesSafeDefaults(t *testing.T) {
	setUserDirs(t, t.TempDir())

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Version != 1 {
		t.Fatalf("Version = %d, want 1", cfg.Version)
	}
	if cfg.Provider.Endpoint != "http://127.0.0.1:11434/v1/chat/completions" {
		t.Fatalf("Endpoint = %q", cfg.Provider.Endpoint)
	}
	if cfg.Provider.API != APIChatCompletions {
		t.Fatalf("API = %q", cfg.Provider.API)
	}
	if cfg.Provider.AllowRemote {
		t.Fatal("AllowRemote = true, want false")
	}
	if cfg.Limits.MaxInputBytes != 16*1024 || cfg.Limits.MaxOutputBytes != 16*1024 {
		t.Fatalf("byte limits = %d/%d", cfg.Limits.MaxInputBytes, cfg.Limits.MaxOutputBytes)
	}
	if cfg.Limits.MaxAuditBytes != audit.DefaultMaxBytes {
		t.Fatalf("MaxAuditBytes = %d, want %d", cfg.Limits.MaxAuditBytes, audit.DefaultMaxBytes)
	}
	if cfg.Limits.Timeout != "120s" || cfg.Limits.MaxConcurrent != 1 {
		t.Fatalf("request limits = timeout %q, concurrency %d", cfg.Limits.Timeout, cfg.Limits.MaxConcurrent)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config is invalid: %v", err)
	}
}

func TestLoadExplicitPartialConfigOverlaysDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, path, `{
  "provider": {"model": "local-test"},
  "limits": {"max_concurrent": 3},
  "audit_dir": "/tmp/turnwire-audit"
}`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Provider.Model != "local-test" {
		t.Fatalf("Model = %q", cfg.Provider.Model)
	}
	if cfg.Provider.Endpoint != defaultEndpoint {
		t.Fatalf("Endpoint = %q, want default %q", cfg.Provider.Endpoint, defaultEndpoint)
	}
	if cfg.Limits.MaxConcurrent != 3 || cfg.Limits.Timeout != defaultTimeout || cfg.Limits.MaxAuditBytes != defaultMaxAuditBytes {
		t.Fatalf("Limits = %+v", cfg.Limits)
	}
	if cfg.AuditDir != "/tmp/turnwire-audit" {
		t.Fatalf("AuditDir = %q", cfg.AuditDir)
	}
}

func TestWriteCreatesRestrictiveConfigAndProtectsExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.json")
	cfg := Default()
	if err := Write(path, cfg, false); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 600", got)
	}
	if err := Write(path, cfg, false); err == nil {
		t.Fatal("Write replaced an existing file without force")
	}
	cfg.Provider.Model = "replacement"
	if err := Write(path, cfg, true); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Provider.Model != "replacement" {
		t.Fatalf("model = %q", loaded.Provider.Model)
	}
}

func TestWriteGuardedRejectsBeforeDestinationMutation(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("descriptor-secured guarded writes are unavailable on this platform")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := Write(path, Default(), false); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	rejected := errors.New("destination rejected")
	guardCalled := false
	cfg := Default()
	cfg.Provider.Model = "must-not-persist"
	err = WriteGuarded(path, cfg, true, func(parent *os.File, name string) error {
		guardCalled = true
		destination, err := owneronly.OpenAtNoFollow(parent, name, os.O_RDONLY, 0)
		if err != nil {
			t.Fatalf("open guarded destination: %v", err)
		}
		defer destination.Close()
		info, err := destination.Stat()
		if err != nil {
			t.Fatalf("inspect guarded destination: %v", err)
		}
		if !os.SameFile(beforeInfo, info) {
			t.Fatal("guard received a different destination parent")
		}
		return rejected
	})
	if !errors.Is(err, rejected) {
		t.Fatalf("WriteGuarded error = %v, want destination rejection", err)
	}
	if !guardCalled {
		t.Fatal("destination guard was not called")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("guarded rejection changed config contents")
	}
	afterInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(beforeInfo, afterInfo) {
		t.Fatal("guarded rejection replaced the config entry")
	}
}

func TestWriteGuardedRetainsOpenedParentAfterSymlinkRetarget(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("descriptor-secured guarded writes are unavailable on this platform")
	}
	root := t.TempDir()
	originalParent := filepath.Join(root, "original", "nested")
	auditParent := filepath.Join(root, "audit", "nested")
	for _, directory := range []string{originalParent, auditParent} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(filepath.Dir(originalParent), alias); err != nil {
		t.Skipf("cannot create parent symlink: %v", err)
	}
	path := filepath.Join(alias, "nested", "config.json")
	originalPath := filepath.Join(originalParent, "config.json")
	auditPath := filepath.Join(auditParent, "config.json")
	auditBefore := []byte("audit sentinel must remain intact\n")
	if err := os.WriteFile(auditPath, auditBefore, 0o600); err != nil {
		t.Fatal(err)
	}
	auditInfo, err := os.Stat(auditPath)
	if err != nil {
		t.Fatal(err)
	}

	guardCalled := false
	cfg := Default()
	cfg.Provider.Model = "written-through-held-parent"
	err = WriteGuarded(path, cfg, true, func(parent *os.File, name string) error {
		guardCalled = true
		if name != "config.json" {
			t.Fatalf("guard entry name = %q", name)
		}
		parentInfo, err := parent.Stat()
		if err != nil {
			t.Fatal(err)
		}
		originalInfo, err := os.Stat(originalParent)
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(parentInfo, originalInfo) {
			t.Fatal("guard did not receive the originally resolved parent")
		}
		if err := os.Remove(alias); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Dir(auditParent), alias); err != nil {
			t.Fatal(err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WriteGuarded: %v", err)
	}
	if !guardCalled {
		t.Fatal("destination guard was not called")
	}
	written, err := Load(originalPath)
	if err != nil {
		t.Fatalf("load config from held parent: %v", err)
	}
	if written.Provider.Model != cfg.Provider.Model {
		t.Fatalf("written model = %q, want %q", written.Provider.Model, cfg.Provider.Model)
	}
	auditAfter, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(auditAfter) != string(auditBefore) {
		t.Fatal("retargeted audit destination was overwritten")
	}
	auditAfterInfo, err := os.Stat(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(auditInfo, auditAfterInfo) {
		t.Fatal("retargeted audit destination was replaced")
	}
	retargetedInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(auditInfo, retargetedInfo) {
		t.Fatal("path was not retargeted to the audit sentinel during the guard")
	}
}

func TestWritePreservesExistingParentPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission test")
	}
	parent := filepath.Join(t.TempDir(), "shared-parent")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "config.json")
	if err := Write(path, Default(), false); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("parent mode = %o, want 755", got)
	}
}

func TestWriteRejectsParentWritableByOtherUsers(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("descriptor-secured Unix writer test")
	}
	parent := filepath.Join(t.TempDir(), "shared-parent")
	if err := os.Mkdir(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "config.json")
	if err := Write(path, Default(), false); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("Write error = %v, want unsafe-directory rejection", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("unsafe parent received a config file: %v", err)
	}
}

func TestWriteRejectsWritableIntermediateSymlinkRedirect(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("descriptor-secured Unix writer test")
	}
	root := t.TempDir()
	shared := filepath.Join(root, "shared")
	if err := os.Mkdir(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	redirect := filepath.Join(shared, "redirect")
	if err := os.Symlink(target, redirect); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	path := filepath.Join(redirect, "nested", "config.json")
	if err := Write(path, Default(), false); err == nil || !strings.Contains(err.Error(), "without sticky-directory protection") {
		t.Fatalf("Write error = %v, want unsafe-ancestor rejection", err)
	}
	if _, err := os.Lstat(filepath.Join(target, "nested")); !os.IsNotExist(err) {
		t.Fatalf("writer followed attacker-controlled intermediate: %v", err)
	}
}

func TestWriteResolvesProtectedAncestorSymlink(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("descriptor-secured Unix writer test")
	}
	root := t.TempDir()
	realParent := filepath.Join(root, "real-parent")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(realParent, alias); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	path := filepath.Join(alias, "nested", "config.json")
	if err := Write(path, Default(), false); err != nil {
		t.Fatalf("Write through protected ancestor symlink: %v", err)
	}
	if _, err := os.Stat(filepath.Join(realParent, "nested", "config.json")); err != nil {
		t.Fatalf("resolved config file: %v", err)
	}
}

func TestWriteSupportsSystemStickyTemporaryAncestor(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("descriptor-secured Unix writer test")
	}
	stickyRoot := "/tmp"
	if runtime.GOOS == "darwin" {
		stickyRoot = "/private/tmp"
	}
	parent, err := os.MkdirTemp(stickyRoot, "turnwire-config-test-")
	if err != nil {
		t.Skipf("cannot create system temporary test directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(parent) })
	if err := Write(filepath.Join(parent, "nested", "config.json"), Default(), false); err != nil {
		t.Fatalf("Write under system sticky temporary ancestor: %v", err)
	}
}

func TestWriteSupportsCurrentUserHomeAncestor(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("descriptor-secured Unix writer test")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	parent, err := os.MkdirTemp(home, ".turnwire-config-test-")
	if err != nil {
		t.Skipf("cannot create home test directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(parent) })
	homeTestDirectory, _, err := owneronly.OpenDirectoryPath(
		parent,
		false,
		owneronly.DirectoryOwnerControlled,
		"current-user home test directory",
	)
	if err != nil {
		// Hosted Linux systems may provision the home path below an ancestor
		// with an ambiguous ACL. The product deliberately rejects that path.
		if runtime.GOOS == "linux" && strings.Contains(err.Error(), "has an ACL that may grant non-owner access") {
			t.Skipf("current-user home does not satisfy the storage policy: %v", err)
		}
		t.Fatalf("validate current-user home storage policy: %v", err)
	}
	if err := homeTestDirectory.Close(); err != nil {
		t.Fatal(err)
	}
	if err := Write(filepath.Join(parent, "nested", "config.json"), Default(), false); err != nil {
		t.Fatalf("Write under current-user home: %v", err)
	}
}

func TestWriteRejectsDirectoryLikeConfigPaths(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("descriptor-secured Unix writer test")
	}
	root := t.TempDir()
	for _, path := range []string{
		root + string(filepath.Separator),
		filepath.Join(root, "child", ".."),
	} {
		if err := Write(path, Default(), false); err == nil {
			t.Fatalf("Write(%q) succeeded for a directory-like path", path)
		}
	}
}

func TestWriteAndLoadRejectConfigSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.json")
	original := []byte("do not overwrite")
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "config.json")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	if err := Write(path, Default(), true); err == nil {
		t.Fatal("Write followed a config symlink")
	}
	contents, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != string(original) {
		t.Fatalf("symlink target changed: %q", contents)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load followed a config symlink")
	}
}

func TestWriteAndLoadResolveDotDotBeforeAncestorSymlinks(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("descriptor-secured Unix config test")
	}
	root := t.TempDir()
	safe := filepath.Join(root, "safe")
	other := filepath.Join(root, "other")
	otherChild := filepath.Join(other, "child")
	for _, directory := range []string{safe, otherChild} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(otherChild, filepath.Join(safe, "link")); err != nil {
		t.Skipf("cannot create ancestor symlink: %v", err)
	}

	otherConfig := Default()
	otherConfig.Provider.Model = "other-model"
	if err := Write(filepath.Join(other, "config.json"), otherConfig, false); err != nil {
		t.Fatal(err)
	}

	separator := string(filepath.Separator)
	aliasPath := safe + separator + "link" + separator + ".." + separator + "config.json"
	safeConfig := Default()
	safeConfig.Provider.Model = "safe-model"
	if err := Write(aliasPath, safeConfig, false); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(aliasPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Provider.Model != safeConfig.Provider.Model {
		t.Fatalf("loaded model = %q, want %q", loaded.Provider.Model, safeConfig.Provider.Model)
	}
}

func TestLoadExplicitMissingFileFails(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "missing.json"))
	if err == nil {
		t.Fatal("Load succeeded, want error")
	}
}

func TestLoadRejectsConfigWritableByOtherUsers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission test")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := Write(path, Default(), false); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o622); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("Load error = %v, want unsafe-permissions rejection", err)
	}
}

func TestLoadRejectsConfigReadableByOtherUsers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission test")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := Write(path, Default(), false); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("Load error = %v, want unsafe-permissions rejection", err)
	}
}

func TestLoadRejectsUnknownFieldsAndTrailingValues(t *testing.T) {
	tests := map[string]string{
		"unknown field":  `{"unexpected": true}`,
		"trailing value": `{}` + "\n" + `{}`,
	}
	for name, contents := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			writeFile(t, path, contents)
			if _, err := Load(path); err == nil {
				t.Fatal("Load succeeded, want error")
			}
		})
	}
}

func TestLoadDoesNotDiscoverConfigFromWorkingDirectory(t *testing.T) {
	setUserDirs(t, t.TempDir())
	working := t.TempDir()
	writeFile(t, filepath.Join(working, "config.json"), `{"version": 999}`)
	t.Chdir(working)

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Version != 1 {
		t.Fatalf("Version = %d, want safe default", cfg.Version)
	}
}

func TestValidateEndpointPolicy(t *testing.T) {
	tests := []struct {
		name        string
		endpoint    string
		allowRemote bool
		wantError   bool
	}{
		{name: "IPv4 loopback HTTP", endpoint: "http://127.0.0.1:11434/v1/chat/completions"},
		{name: "entire IPv4 loopback range", endpoint: "http://127.42.0.9/v1/chat/completions"},
		{name: "IPv6 loopback HTTP", endpoint: "http://[::1]:11434/v1/chat/completions"},
		{name: "localhost HTTP denied", endpoint: "http://localhost:11434/v1/chat/completions", wantError: true},
		{name: "loopback trailing dot denied", endpoint: "http://127.0.0.1.:11434/v1/chat/completions", wantError: true},
		{name: "literal loopback HTTPS", endpoint: "https://127.0.0.1/v1/chat/completions"},
		{name: "localhost HTTPS needs remote opt in", endpoint: "https://localhost/v1/chat/completions", wantError: true},
		{name: "localhost HTTPS explicitly allowed", endpoint: "https://localhost/v1/chat/completions", allowRemote: true},
		{name: "remote HTTP denied", endpoint: "http://example.com/v1/chat/completions", wantError: true},
		{name: "remote HTTP denied even when allowed", endpoint: "http://example.com/v1/chat/completions", allowRemote: true, wantError: true},
		{name: "remote HTTPS needs opt in", endpoint: "https://example.com/v1/chat/completions", wantError: true},
		{name: "remote HTTPS explicitly allowed", endpoint: "https://example.com/v1/chat/completions", allowRemote: true},
		{name: "lookalike localhost denied", endpoint: "http://localhost.example.com/v1/chat/completions", wantError: true},
		{name: "unsupported scheme", endpoint: "file:///tmp/model", wantError: true},
		{name: "relative URL", endpoint: "/v1/chat/completions", wantError: true},
		{name: "missing host", endpoint: "http:///v1/chat/completions", wantError: true},
		{name: "empty hostname authority", endpoint: "https://:443/v1/chat/completions", allowRemote: true, wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := defaultConfig()
			cfg.Provider.Endpoint = tt.endpoint
			cfg.Provider.AllowRemote = tt.allowRemote
			err := cfg.Validate()
			if (err != nil) != tt.wantError {
				t.Fatalf("Validate() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidateFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "version", mutate: func(c *Config) { c.Version = 2 }},
		{name: "model", mutate: func(c *Config) { c.Provider.Model = "  " }},
		{name: "API", mutate: func(c *Config) { c.Provider.API = "completions" }},
		{name: "API key environment name", mutate: func(c *Config) { c.Provider.APIKeyEnv = "BAD-NAME" }},
		{name: "input bytes", mutate: func(c *Config) { c.Limits.MaxInputBytes = 0 }},
		{name: "input bytes too large", mutate: func(c *Config) { c.Limits.MaxInputBytes = maxMessageBytes + 1 }},
		{name: "output bytes", mutate: func(c *Config) { c.Limits.MaxOutputBytes = -1 }},
		{name: "output bytes too large", mutate: func(c *Config) { c.Limits.MaxOutputBytes = maxMessageBytes + 1 }},
		{name: "audit bytes", mutate: func(c *Config) { c.Limits.MaxAuditBytes = 0 }},
		{name: "audit bytes too large", mutate: func(c *Config) { c.Limits.MaxAuditBytes = maxAuditBytes + 1 }},
		{name: "timeout syntax", mutate: func(c *Config) { c.Limits.Timeout = "soon" }},
		{name: "timeout positive", mutate: func(c *Config) { c.Limits.Timeout = "0s" }},
		{name: "concurrency", mutate: func(c *Config) { c.Limits.MaxConcurrent = 0 }},
		{name: "concurrency too large", mutate: func(c *Config) { c.Limits.MaxConcurrent = maxConcurrentRequests + 1 }},
		{name: "relative audit directory", mutate: func(c *Config) { c.AuditDir = "relative/audit" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := defaultConfig()
			tt.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("Validate succeeded, want error")
			}
		})
	}
}

func TestValidateRejectsNonCleanAuditDirectory(t *testing.T) {
	cfg := defaultConfig()
	clean := filepath.Join(t.TempDir(), "audit")
	cfg.AuditDir = clean + string(filepath.Separator) + ".." + string(filepath.Separator) + filepath.Base(clean)
	if filepath.Clean(cfg.AuditDir) == cfg.AuditDir {
		t.Fatal("test audit path is unexpectedly clean")
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "lexically clean") {
		t.Fatalf("Validate() error = %v, want lexical-cleanliness error", err)
	}
}

func TestValidationErrorsDoNotExposeEndpointCredentials(t *testing.T) {
	cfg := defaultConfig()
	cfg.Provider.Endpoint = "https://turnwire-user:TOP-SECRET@example.com/v1/chat/completions"
	cfg.Provider.AllowRemote = true
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate succeeded, want error")
	}
	if strings.Contains(err.Error(), "TOP-SECRET") || strings.Contains(err.Error(), "turnwire-user") {
		t.Fatalf("error exposed endpoint credentials: %v", err)
	}

	cfg = defaultConfig()
	cfg.Limits.Timeout = "TOP-SECRET"
	err = cfg.Validate()
	if err == nil {
		t.Fatal("Validate succeeded, want error")
	}
	if strings.Contains(err.Error(), "TOP-SECRET") {
		t.Fatalf("error exposed invalid config value: %v", err)
	}
}

func TestDefaultPaths(t *testing.T) {
	root := t.TempDir()
	setUserDirs(t, root)

	configPath := DefaultConfigPath()
	if filepath.Base(configPath) != "config.json" || filepath.Base(filepath.Dir(configPath)) != "turnwire" {
		t.Fatalf("DefaultConfigPath() = %q", configPath)
	}
	dataDir := DefaultDataDir()
	if filepath.Base(dataDir) != "turnwire" {
		t.Fatalf("DefaultDataDir() = %q", dataDir)
	}
}

func setUserDirs(t *testing.T, root string) {
	t.Helper()
	t.Setenv("HOME", root)
	t.Setenv("USERPROFILE", root)
	t.Setenv("APPDATA", filepath.Join(root, "AppData", "Roaming"))
	t.Setenv("LOCALAPPDATA", filepath.Join(root, "AppData", "Local"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, ".config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, ".local", "state"))

	if runtime.GOOS == "windows" {
		// os.UserConfigDir requires APPDATA on Windows; setting both paths keeps
		// this helper explicit about config versus durable state.
		t.Setenv("APPDATA", filepath.Join(root, "AppData", "Roaming"))
	}
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
