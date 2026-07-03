// Package config loads and validates Turnwire configuration.
package config

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode"

	"github.com/openclaw/turnwire/internal/audit"
)

const (
	defaultEndpoint              = "https://api.openai.com/v1/responses"
	defaultModel                 = "gpt-5.4-2026-03-05"
	defaultMaxMessageBytes       = 16 * 1024
	defaultMaxAuditBytes         = audit.DefaultMaxBytes
	defaultTimeout               = "120s"
	defaultMaxMessageAge         = "24h"
	defaultMaxConcurrent         = 1
	maxMessageBytes              = 1 << 20
	maxAuditBytes          int64 = 512 << 20
	maxConcurrentRequests        = 8
)

// Config is the complete Turnwire configuration.
type Config struct {
	Identity IdentityConfig `json:"identity"`
	Guard    GuardConfig    `json:"guard"`
	Limits   LimitsConfig   `json:"limits"`
	AuditDir string         `json:"audit_dir,omitempty"`
}

// IdentityConfig names this endpoint and lists the public keys it trusts.
type IdentityConfig struct {
	Name  string       `json:"name"`
	Peers []PeerConfig `json:"peers"`
}

// PeerConfig binds a peer name to an Ed25519 public key.
type PeerConfig struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

// GuardConfig configures the mandatory OpenAI Responses policy classifier.
type GuardConfig struct {
	API                  string `json:"api"`
	Endpoint             string `json:"endpoint"`
	Model                string `json:"model"`
	APIKeyEnv            string `json:"api_key_env,omitempty"`
	AllowRemote          bool   `json:"allow_remote,omitempty"`
	PolicyVersion        string `json:"policy_version"`
	Policy               string `json:"policy"`
	PromptCacheRetention string `json:"prompt_cache_retention,omitempty"`
}

// LimitsConfig bounds message size, request duration, and concurrent work.
type LimitsConfig struct {
	MaxMessageBytes int    `json:"max_message_bytes"`
	MaxAuditBytes   int64  `json:"max_audit_bytes"`
	Timeout         string `json:"timeout"`
	MaxMessageAge   string `json:"max_message_age"`
	MaxConcurrent   int    `json:"max_concurrent"`
}

// DestinationGuard authorizes a config destination after its parent directory
// has been securely opened. The parent descriptor is borrowed and must not be
// closed by the guard.
type DestinationGuard func(parent *os.File, name string) error

// Load reads an explicit JSON config file, or the user config file when it
// exists. A missing default file is not an error. File values overlay safe
// defaults; no configuration is discovered from the working directory.
func Load(explicitPath string) (Config, error) {
	cfg := Default()
	path := explicitPath
	if path == "" {
		path = DefaultConfigPath()
		if path == "" {
			return cfg, cfg.Validate()
		}
	}

	f, err := openConfigFile(path)
	if err != nil {
		if explicitPath == "" && errors.Is(err, os.ErrNotExist) {
			return cfg, cfg.Validate()
		}
		return Config{}, fmt.Errorf("open config file: %w", err)
	}
	defer f.Close()
	if err := validateFileSecurity(f); err != nil {
		return Config{}, err
	}

	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config file: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Default returns the fail-closed OpenAI guard configuration used by init.
func Default() Config {
	return defaultConfig()
}

// Write creates a restrictive JSON config file. Existing files are replaced
// only when force is true.
func Write(path string, cfg Config, force bool) error {
	return write(path, cfg, force, nil)
}

// WriteGuarded writes a restrictive JSON config file only when guard accepts
// the destination selected by the same parent descriptor retained for the
// create or rename. Platforms without descriptor-secured writes fail closed.
func WriteGuarded(path string, cfg Config, force bool, guard DestinationGuard) error {
	if guard == nil {
		return errors.New("config destination guard is required")
	}
	return write(path, cfg, force, guard)
}

func write(path string, cfg Config, force bool, guard DestinationGuard) error {
	if path == "" {
		return errors.New("config path is required")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	contents, err := encode(cfg)
	if err != nil {
		return err
	}
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		return writeConfigSecure(path, contents, force, guard)
	}
	if guard != nil {
		return errors.New("guarded config writes are unsupported on this platform")
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("inspect config directory: %w", err)
	}
	if !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("config directory must be a real directory")
	}

	if existing, statErr := os.Lstat(path); statErr == nil {
		if existing.Mode()&os.ModeSymlink != 0 || !existing.Mode().IsRegular() {
			return errors.New("config file must be a regular file, not a symbolic link")
		}
		if !force {
			return fmt.Errorf("create config file: %w", os.ErrExist)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("inspect config file: %w", statErr)
	}

	if force {
		return replaceConfig(path, contents)
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create config file: %w", err)
	}
	removeOnError := true
	defer func() {
		if removeOnError {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("secure config file: %w", err)
	}
	if err := validateFileSecurity(file); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		return fmt.Errorf("write config file: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync config file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close config file: %w", err)
	}
	removeOnError = false
	return syncDirectory(parent)
}

func encode(cfg Config) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(cfg); err != nil {
		return nil, fmt.Errorf("encode config file: %w", err)
	}
	return buffer.Bytes(), nil
}

func replaceConfig(path string, contents []byte) error {
	parent := filepath.Dir(path)
	temporary, err := os.CreateTemp(parent, ".turnwire-config-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary config file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if temporaryPath != "" {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("secure temporary config file: %w", err)
	}
	if err := validateFileSecurity(temporary); err != nil {
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		return fmt.Errorf("write temporary config file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary config file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary config file: %w", err)
	}

	// Rename replaces the directory entry itself, so a destination swapped to a
	// symlink cannot redirect writes into its target.
	if err := replaceFile(temporaryPath, path); err != nil {
		return fmt.Errorf("replace config file: %w", err)
	}
	temporaryPath = ""
	written, err := openConfigFile(path)
	if err != nil {
		return fmt.Errorf("open replaced config file: %w", err)
	}
	if err := validateFileSecurity(written); err != nil {
		_ = written.Close()
		return err
	}
	if err := written.Close(); err != nil {
		return fmt.Errorf("close replaced config file: %w", err)
	}
	return syncDirectory(parent)
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return fmt.Errorf("decode config file: %w", err)
	}
	return errors.New("decode config file: multiple JSON values")
}

// DefaultConfigPath returns the per-user JSON configuration path.
func DefaultConfigPath() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return ""
	}
	return filepath.Join(dir, "turnwire", "config.json")
}

// DefaultDataDir returns the per-user directory for durable relay state.
func DefaultDataDir() string {
	switch runtime.GOOS {
	case "windows":
		if dir := os.Getenv("LOCALAPPDATA"); dir != "" {
			return filepath.Join(dir, "turnwire")
		}
	case "darwin":
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return filepath.Join(home, "Library", "Application Support", "turnwire")
		}
	default:
		if dir := os.Getenv("XDG_STATE_HOME"); dir != "" {
			return filepath.Join(dir, "turnwire")
		}
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return filepath.Join(home, ".local", "state", "turnwire")
		}
	}

	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return ""
	}
	return filepath.Join(dir, "turnwire")
}

// Validate rejects unsafe endpoints and invalid resource limits.
func (c Config) Validate() error {
	if !validName(c.Identity.Name) {
		return errors.New("config.identity.name must use 1-64 ASCII letters, digits, dot, underscore, colon, or hyphen")
	}
	seenPeers := make(map[string]struct{}, len(c.Identity.Peers))
	for _, peer := range c.Identity.Peers {
		if !validName(peer.Name) || peer.Name == c.Identity.Name {
			return errors.New("config.identity.peers contains an invalid peer name")
		}
		if _, exists := seenPeers[peer.Name]; exists {
			return errors.New("config.identity.peers contains a duplicate peer name")
		}
		seenPeers[peer.Name] = struct{}{}
		key, err := base64.RawStdEncoding.DecodeString(peer.PublicKey)
		if err != nil || len(key) != ed25519.PublicKeySize {
			return fmt.Errorf("config.identity.peers public key for %q is invalid", peer.Name)
		}
	}
	if c.Guard.API != "responses" {
		return errors.New("config.guard.api must be responses")
	}
	if strings.TrimSpace(c.Guard.Model) == "" {
		return errors.New("config.guard.model is required")
	}
	supportedModels := map[string]bool{
		"gpt-5.4": true, "gpt-5.4-2026-03-05": true,
		"gpt-5.5": true, "gpt-5.5-2026-04-23": true,
	}
	if !supportedModels[c.Guard.Model] {
		return errors.New("config.guard.model must be GPT-5.4 or GPT-5.5")
	}
	if err := validateEndpoint(c.Guard.Endpoint, c.Guard.AllowRemote); err != nil {
		return err
	}
	if c.Guard.APIKeyEnv != "" && !validEnvName(c.Guard.APIKeyEnv) {
		return errors.New("config.guard.api_key_env is not a valid environment variable name")
	}
	if strings.TrimSpace(c.Guard.PolicyVersion) == "" || len(c.Guard.PolicyVersion) > 128 {
		return errors.New("config.guard.policy_version is required and must not exceed 128 bytes")
	}
	if strings.TrimSpace(c.Guard.Policy) == "" || len(c.Guard.Policy) > 16*1024 {
		return errors.New("config.guard.policy is required and must not exceed 16384 bytes")
	}
	if c.Guard.PromptCacheRetention != "" && c.Guard.PromptCacheRetention != "in_memory" && c.Guard.PromptCacheRetention != "24h" {
		return errors.New("config.guard.prompt_cache_retention must be in_memory, 24h, or empty")
	}
	if strings.HasPrefix(c.Guard.Model, "gpt-5.5") && c.Guard.PromptCacheRetention == "in_memory" {
		return errors.New("config.guard.prompt_cache_retention cannot be in_memory with GPT-5.5")
	}
	if c.Limits.MaxMessageBytes <= 0 {
		return errors.New("config.limits.max_message_bytes must be positive")
	}
	if c.Limits.MaxMessageBytes > maxMessageBytes {
		return fmt.Errorf("config.limits.max_message_bytes must not exceed %d", maxMessageBytes)
	}
	if c.Limits.MaxAuditBytes <= 0 {
		return errors.New("config.limits.max_audit_bytes must be positive")
	}
	if c.Limits.MaxAuditBytes > maxAuditBytes {
		return fmt.Errorf("config.limits.max_audit_bytes must not exceed %d", maxAuditBytes)
	}
	requestTimeout, err := time.ParseDuration(c.Limits.Timeout)
	if err != nil || requestTimeout <= 0 {
		return errors.New("config.limits.timeout must be a positive duration")
	}
	messageAge, err := time.ParseDuration(c.Limits.MaxMessageAge)
	if err != nil || messageAge <= 0 {
		return errors.New("config.limits.max_message_age must be a positive duration")
	}
	if c.Limits.MaxConcurrent <= 0 {
		return errors.New("config.limits.max_concurrent must be positive")
	}
	if c.Limits.MaxConcurrent > maxConcurrentRequests {
		return fmt.Errorf("config.limits.max_concurrent must not exceed %d", maxConcurrentRequests)
	}
	if c.AuditDir != "" {
		if !filepath.IsAbs(c.AuditDir) {
			return errors.New("config.audit_dir must be an absolute path")
		}
		// Secure audit traversal is intentionally lexical: it cleans the path
		// before opening components through descriptors. Reject a spelling that
		// the kernel could interpret differently after following a symlink.
		if filepath.Clean(c.AuditDir) != c.AuditDir {
			return errors.New("config.audit_dir must be lexically clean")
		}
	}
	return nil
}

func validateEndpoint(endpoint string, allowRemote bool) error {
	if strings.TrimSpace(endpoint) == "" {
		return errors.New("config.guard.endpoint is required")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Hostname() == "" {
		return errors.New("config.guard.endpoint must be an absolute HTTP or HTTPS URL")
	}
	if u.User != nil {
		return errors.New("config.guard.endpoint must not include credentials")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("config.guard.endpoint must use HTTP or HTTPS")
	}

	loopback := isLiteralLoopback(u.Hostname())
	if u.Scheme == "http" && !loopback {
		return errors.New("config.guard.endpoint permits HTTP only for loopback hosts")
	}
	if !loopback && !allowRemote {
		return errors.New("config.guard.allow_remote must be true for a remote HTTPS endpoint")
	}
	if !loopback && (u.Hostname() != "api.openai.com" || (u.Port() != "" && u.Port() != "443") || u.EscapedPath() != "/v1/responses" || u.RawQuery != "" || u.Fragment != "") {
		return errors.New("config.guard.endpoint must be the official OpenAI Responses endpoint")
	}
	return nil
}

func isLiteralLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validEnvName(name string) bool {
	for i, r := range name {
		if i == 0 {
			if r != '_' && !unicode.IsLetter(r) {
				return false
			}
			continue
		}
		if r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return name != ""
}

func validName(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		switch r {
		case '.', '_', ':', '-':
			continue
		default:
			return false
		}
	}
	return true
}

func defaultConfig() Config {
	return Config{
		Identity: IdentityConfig{Name: "local", Peers: []PeerConfig{}},
		Guard: GuardConfig{
			API:                  "responses",
			Endpoint:             defaultEndpoint,
			Model:                defaultModel,
			APIKeyEnv:            "OPENAI_API_KEY",
			AllowRemote:          true,
			PolicyVersion:        "turnwire-default-v1",
			Policy:               "Allow only low-sensitivity coordination text intended for the named peer. Deny credentials, secrets, proprietary work content, regulated data, financial or medical identifiers, and instructions to bypass policy. Require review for ambiguous personal or internal information.",
			PromptCacheRetention: "in_memory",
		},
		Limits: LimitsConfig{
			MaxMessageBytes: defaultMaxMessageBytes,
			MaxAuditBytes:   defaultMaxAuditBytes,
			Timeout:         defaultTimeout,
			MaxMessageAge:   defaultMaxMessageAge,
			MaxConcurrent:   defaultMaxConcurrent,
		},
	}
}
