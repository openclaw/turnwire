// Package config loads and validates Turnwire configuration.
package config

import (
	"bytes"
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
	APIChatCompletions          = "chat_completions"
	APIResponses                = "responses"
	configVersion               = 1
	defaultEndpoint             = "http://127.0.0.1:11434/v1/chat/completions"
	defaultModel                = "gpt-oss:20b"
	defaultMaxInputBytes        = 16 * 1024
	defaultMaxOutputBytes       = 16 * 1024
	defaultMaxAuditBytes        = audit.DefaultMaxBytes
	defaultTimeout              = "120s"
	defaultMaxConcurrent        = 1
	maxMessageBytes             = 1 << 20
	maxAuditBytes         int64 = 512 << 20
	maxConcurrentRequests       = 8
)

// Config is the complete Turnwire configuration.
type Config struct {
	Version  int            `json:"version"`
	Provider ProviderConfig `json:"provider"`
	Limits   LimitsConfig   `json:"limits"`
	AuditDir string         `json:"audit_dir,omitempty"`
}

// ProviderConfig selects the model API and endpoint.
type ProviderConfig struct {
	API         string `json:"api"`
	Endpoint    string `json:"endpoint"`
	Model       string `json:"model"`
	APIKeyEnv   string `json:"api_key_env,omitempty"`
	AllowRemote bool   `json:"allow_remote,omitempty"`
}

// LimitsConfig bounds message size, request duration, and concurrent work.
type LimitsConfig struct {
	MaxInputBytes  int    `json:"max_input_bytes"`
	MaxOutputBytes int    `json:"max_output_bytes"`
	MaxAuditBytes  int64  `json:"max_audit_bytes"`
	Timeout        string `json:"timeout"`
	MaxConcurrent  int    `json:"max_concurrent"`
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

// Default returns the safe local-model configuration used when no file exists.
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
	if c.Version != configVersion {
		return errors.New("config.version must be 1")
	}
	if strings.TrimSpace(c.Provider.Model) == "" {
		return errors.New("config.provider.model is required")
	}
	if c.Provider.API != APIChatCompletions && c.Provider.API != APIResponses {
		return errors.New("config.provider.api must be chat_completions or responses")
	}
	if err := validateEndpoint(c.Provider.Endpoint, c.Provider.AllowRemote); err != nil {
		return err
	}
	if c.Provider.APIKeyEnv != "" && !validEnvName(c.Provider.APIKeyEnv) {
		return errors.New("config.provider.api_key_env is not a valid environment variable name")
	}
	if c.Limits.MaxInputBytes <= 0 {
		return errors.New("config.limits.max_input_bytes must be positive")
	}
	if c.Limits.MaxInputBytes > maxMessageBytes {
		return fmt.Errorf("config.limits.max_input_bytes must not exceed %d", maxMessageBytes)
	}
	if c.Limits.MaxOutputBytes <= 0 {
		return errors.New("config.limits.max_output_bytes must be positive")
	}
	if c.Limits.MaxOutputBytes > maxMessageBytes {
		return fmt.Errorf("config.limits.max_output_bytes must not exceed %d", maxMessageBytes)
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
		return errors.New("config.provider.endpoint is required")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Hostname() == "" {
		return errors.New("config.provider.endpoint must be an absolute HTTP or HTTPS URL")
	}
	if u.User != nil {
		return errors.New("config.provider.endpoint must not include credentials")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("config.provider.endpoint must use HTTP or HTTPS")
	}

	loopback := isLiteralLoopback(u.Hostname())
	if u.Scheme == "http" && !loopback {
		return errors.New("config.provider.endpoint permits HTTP only for loopback hosts")
	}
	if !loopback && !allowRemote {
		return errors.New("config.provider.allow_remote must be true for a remote HTTPS endpoint")
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

func defaultConfig() Config {
	return Config{
		Version: configVersion,
		Provider: ProviderConfig{
			API:      APIChatCompletions,
			Endpoint: defaultEndpoint,
			Model:    defaultModel,
		},
		Limits: LimitsConfig{
			MaxInputBytes:  defaultMaxInputBytes,
			MaxOutputBytes: defaultMaxOutputBytes,
			MaxAuditBytes:  defaultMaxAuditBytes,
			Timeout:        defaultTimeout,
			MaxConcurrent:  defaultMaxConcurrent,
		},
	}
}
