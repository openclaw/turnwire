package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/openclaw/turnwire/internal/audit"
	"github.com/openclaw/turnwire/internal/buildinfo"
	"github.com/openclaw/turnwire/internal/config"
	"github.com/openclaw/turnwire/internal/mailbox"
	"github.com/openclaw/turnwire/internal/mcpserver"
	"github.com/openclaw/turnwire/internal/responder"
)

const probeText = "Turnwire connectivity probe. Reply with OK."

func runInit(args []string, opts options, stdout io.Writer) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	var force, allowRemote bool
	var provider, api, endpoint, model, apiKeyEnv string
	flags.BoolVar(&force, "force", false, "replace an existing configuration")
	flags.StringVar(&provider, "provider", "", "built-in provider preset")
	flags.StringVar(&api, "api", "", "model API")
	flags.StringVar(&endpoint, "endpoint", "", "model API endpoint")
	flags.StringVar(&model, "model", "", "model name")
	flags.StringVar(&apiKeyEnv, "api-key-env", "", "API key environment variable")
	flags.BoolVar(&allowRemote, "allow-remote", false, "permit a remote HTTPS endpoint")
	rest, help, err := parseFlags(flags, args, stdout, initHelp)
	if err != nil || help {
		return err
	}
	if err := requireNoArgs(rest); err != nil {
		return err
	}

	cfg := config.Default()
	if provider != "" && provider != "openai" {
		return usageError("unsupported provider preset %q", provider)
	}
	if provider == "openai" {
		if api != "" || endpoint != "" {
			return usageError("--provider openai cannot be combined with --api or --endpoint")
		}
		cfg.Provider.API = config.APIResponses
		cfg.Provider.Endpoint = "https://api.openai.com/v1/responses"
		cfg.Provider.Model = "gpt-5.5"
		cfg.Provider.APIKeyEnv = "OPENAI_API_KEY"
		cfg.Provider.AllowRemote = true
	}
	if api != "" {
		cfg.Provider.API = api
	}
	if endpoint != "" {
		cfg.Provider.Endpoint = endpoint
	}
	if model != "" {
		cfg.Provider.Model = model
	}
	if apiKeyEnv != "" {
		cfg.Provider.APIKeyEnv = apiKeyEnv
	}
	if allowRemote {
		cfg.Provider.AllowRemote = true
	}

	configPath := opts.configPath
	if configPath == "" {
		configPath = config.DefaultConfigPath()
	}
	if configPath == "" {
		return errors.New("cannot determine the default config path; use --config")
	}
	cfg.AuditDir, err = resolveAuditDir(cfg, opts.dataDir)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return usageError("%v", err)
	}
	log, err := openWritableAudit(cfg.AuditDir, cfg.Limits.MaxAuditBytes)
	if err != nil {
		return fmt.Errorf("initialize audit log: %w", err)
	}
	// Preserve a clear error for ordinary aliases such as a final symlink. The
	// descriptor guard below remains authoritative and closes the check/reopen
	// gap for the actual destination selected by the config writer.
	aliasesAudit, err := log.AliasesPath(configPath)
	if err != nil {
		return errors.Join(fmt.Errorf("validate config path: %w", err), log.Close())
	}
	if aliasesAudit {
		return errors.Join(errors.New("config path must not name the audit log"), log.Close())
	}
	guard := func(parent *os.File, name string) error {
		aliasesAudit, err := log.AliasesEntry(parent, name)
		if err != nil {
			return fmt.Errorf("validate config path: %w", err)
		}
		if aliasesAudit {
			return errors.New("config path must not name the audit log")
		}
		return nil
	}
	if err := config.WriteGuarded(configPath, cfg, force, guard); err != nil {
		return errors.Join(err, log.Close())
	}
	if err := log.Close(); err != nil {
		return fmt.Errorf("close audit log: %w", err)
	}

	if !opts.quiet {
		lines := []string{
			"Initialized Turnwire\n",
			fmt.Sprintf("Config: %s\n", strconv.Quote(configPath)),
			fmt.Sprintf("Audit:  %s\n", strconv.Quote(cfg.AuditDir)),
			"Next:   turnwire doctor\n",
		}
		for _, line := range lines {
			if err := writeOutput(stdout, []byte(line)); err != nil {
				return fmt.Errorf("write init status: %w", err)
			}
		}
	}
	return nil
}

func runServe(ctx context.Context, args []string, opts options, stdin io.Reader, stdout, stderr io.Writer) error {
	return runServeWithResponder(ctx, args, opts, stdin, stdout, stderr, func(cfg responder.HTTPConfig) (responder.Responder, error) {
		return responder.NewHTTP(cfg)
	})
}

func runServeWithResponder(
	ctx context.Context,
	args []string,
	opts options,
	stdin io.Reader,
	stdout, stderr io.Writer,
	newResponder func(responder.HTTPConfig) (responder.Responder, error),
) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	rest, help, err := parseFlags(flags, args, stdout, serveHelp)
	if err != nil || help {
		return err
	}
	if err := requireNoArgs(rest); err != nil {
		return err
	}
	if terminalReader(stdin) {
		return usageError("serve expects an MCP client over stdin; run turnwire doctor for an interactive check")
	}

	cfg, err := config.Load(opts.configPath)
	if err != nil {
		return err
	}
	auditDir, err := resolveAuditDir(cfg, opts.dataDir)
	if err != nil {
		return err
	}
	log, err := openWritableAudit(auditDir, cfg.Limits.MaxAuditBytes)
	if err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	defer log.Close()

	model, err := newResponder(responder.HTTPConfig{
		API:            cfg.Provider.API,
		Endpoint:       cfg.Provider.Endpoint,
		Model:          cfg.Provider.Model,
		APIKeyEnv:      cfg.Provider.APIKeyEnv,
		MaxOutputBytes: cfg.Limits.MaxOutputBytes,
	})
	if err != nil {
		return err
	}
	timeout, err := time.ParseDuration(cfg.Limits.Timeout)
	if err != nil {
		return errors.New("configured timeout is invalid")
	}
	service, err := mailbox.New(mailbox.Options{
		Audit:          log,
		Responder:      model,
		MaxInputBytes:  cfg.Limits.MaxInputBytes,
		MaxOutputBytes: cfg.Limits.MaxOutputBytes,
		Timeout:        timeout,
		MaxConcurrent:  cfg.Limits.MaxConcurrent,
	})
	if err != nil {
		return err
	}
	if opts.verbose {
		fmt.Fprintln(stderr, "turnwire: serving MCP over stdio")
	}
	serveErr := mcpserver.Run(ctx, service, buildinfo.Current().Version, stdin, stdout, cfg.Limits.MaxInputBytes, cfg.Limits.MaxConcurrent)
	// MCP Run normally performs the coordinated drain. Repeat it idempotently to
	// cover validation or connection exits before its lifecycle watcher starts.
	if err := service.Shutdown(context.Background()); err != nil {
		return errors.New("turnwire shutdown failed")
	}
	if serveErr != nil {
		if ctx.Err() != nil {
			return nil
		}
		// Transport and SDK errors can include peer-controlled JSON, terminal
		// control bytes, provider details, or local paths. Keep the CLI boundary
		// fixed just as tool errors are fixed at the MCP boundary.
		return errors.New("MCP transport failed")
	}
	return nil
}

func requireAuditCapacity(log *audit.Log) error {
	usedBytes, maxBytes, err := log.Usage()
	if err != nil {
		return err
	}
	if usedBytes >= maxBytes {
		return audit.ErrQuotaExceeded
	}
	return nil
}

func openWritableAudit(dir string, maxBytes int64) (*audit.Log, error) {
	log, err := audit.OpenWithQuota(dir, maxBytes)
	if err != nil {
		return nil, err
	}
	if err := requireAuditCapacity(log); err != nil {
		return nil, errors.Join(err, log.Close())
	}
	return log, nil
}

type doctorCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type doctorReport struct {
	OK     bool          `json:"ok"`
	Checks []doctorCheck `json:"checks"`
}

func runDoctor(ctx context.Context, args []string, opts options, stdout io.Writer) error {
	return runDoctorWithDependencies(ctx, args, opts, stdout, doctorDependencies{
		loadConfig:  config.Load,
		verifyAudit: verifyWritableAuditDir,
		lookupEnv:   os.LookupEnv,
		probe:       probeProvider,
	})
}

type doctorDependencies struct {
	loadConfig  func(string) (config.Config, error)
	verifyAudit func(string, int64) error
	lookupEnv   func(string) (string, bool)
	probe       func(context.Context, config.Config) error
}

func runDoctorWithDependencies(
	ctx context.Context,
	args []string,
	opts options,
	stdout io.Writer,
	deps doctorDependencies,
) error {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	var probe, asJSON bool
	flags.BoolVar(&probe, "probe", false, "probe the configured model")
	flags.BoolVar(&asJSON, "json", false, "emit JSON")
	rest, help, err := parseFlags(flags, args, stdout, doctorHelp)
	if err != nil || help {
		return err
	}
	if err := requireNoArgs(rest); err != nil {
		return err
	}

	report := doctorReport{OK: true, Checks: make([]doctorCheck, 0, 4)}
	add := func(name string, err error, success string) {
		if err != nil {
			report.OK = false
			report.Checks = append(report.Checks, doctorCheck{Name: name, Status: "fail", Message: safeDoctorError(name, err)})
			return
		}
		report.Checks = append(report.Checks, doctorCheck{Name: name, Status: "pass", Message: success})
	}

	cfg, loadErr := deps.loadConfig(opts.configPath)
	add("config", loadErr, "configuration is valid")
	if loadErr == nil {
		auditDir, pathErr := resolveAuditDir(cfg, opts.dataDir)
		var auditErr error
		if pathErr != nil {
			auditErr = pathErr
		} else {
			auditErr = deps.verifyAudit(auditDir, cfg.Limits.MaxAuditBytes)
		}
		add("audit", auditErr, "audit chain and permissions are valid")

		// Audit/platform validation is the authorization boundary for all
		// provider-side activity, including merely reading an API key. Do not
		// inspect credentials or construct/contact the provider after a storage
		// prerequisite fails.
		if auditErr == nil {
			var credentialErr error
			if cfg.Provider.APIKeyEnv == "" {
				add("credentials", nil, "provider does not require an API key")
			} else if value, ok := deps.lookupEnv(cfg.Provider.APIKeyEnv); !ok || value == "" {
				credentialErr = errors.New("configured API key environment variable is empty")
				add("credentials", credentialErr, "")
			} else {
				add("credentials", nil, "configured API key is available")
			}

			if probe && credentialErr == nil {
				probeErr := deps.probe(ctx, cfg)
				add("provider", probeErr, "fixed model probe succeeded")
			}
		}
	}

	if asJSON {
		if err := writeJSONOutput(stdout, report); err != nil {
			return fmt.Errorf("write doctor report: %w", err)
		}
	} else {
		for _, check := range report.Checks {
			line := fmt.Sprintf("%s %-11s %s\n", stringsUpper(check.Status), check.Name, strconv.QuoteToGraphic(check.Message))
			if err := writeOutput(stdout, []byte(line)); err != nil {
				return fmt.Errorf("write doctor report: %w", err)
			}
		}
		if report.OK {
			if err := writeOutput(stdout, []byte("Turnwire is ready.\n")); err != nil {
				return fmt.Errorf("write doctor report: %w", err)
			}
		}
	}
	if !report.OK {
		return reportedError(errors.New("one or more doctor checks failed"))
	}
	return nil
}

func safeDoctorError(name string, err error) string {
	if name == "provider" {
		// Network client errors may include URLs. Keep query strings and other
		// accidentally embedded credentials out of diagnostics.
		return "fixed model probe failed"
	}
	return err.Error()
}

func probeProvider(ctx context.Context, cfg config.Config) error {
	model, err := responder.NewHTTP(responder.HTTPConfig{
		API:            cfg.Provider.API,
		Endpoint:       cfg.Provider.Endpoint,
		Model:          cfg.Provider.Model,
		APIKeyEnv:      cfg.Provider.APIKeyEnv,
		MaxOutputBytes: cfg.Limits.MaxOutputBytes,
	})
	if err != nil {
		return err
	}
	timeout, err := time.ParseDuration(cfg.Limits.Timeout)
	if err != nil {
		return errors.New("configured timeout is invalid")
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	_, err = model.Respond(probeCtx, probeText)
	return err
}

func runVersion(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("version", flag.ContinueOnError)
	var asJSON bool
	flags.BoolVar(&asJSON, "json", false, "emit JSON")
	rest, help, err := parseFlags(flags, args, stdout, versionHelp)
	if err != nil || help {
		return err
	}
	if err := requireNoArgs(rest); err != nil {
		return err
	}
	if asJSON {
		if err := writeJSONOutput(stdout, buildinfo.Current()); err != nil {
			return fmt.Errorf("write version: %w", err)
		}
		return nil
	}
	if err := writeOutput(stdout, []byte(versionLine())); err != nil {
		return fmt.Errorf("write version: %w", err)
	}
	return nil
}

func writeJSONOutput(w io.Writer, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return writeOutput(w, encoded)
}

func resolveAuditDir(cfg config.Config, dataDir string) (string, error) {
	// An explicit command-line data root overrides configuration. Without that
	// override, retain the absolute audit path written by init before falling
	// back to the platform default data root.
	if dataDir == "" && cfg.AuditDir != "" {
		return cfg.AuditDir, nil
	}
	if dataDir == "" {
		dataDir = config.DefaultDataDir()
		if dataDir == "" {
			return "", errors.New("cannot determine the default data directory; use --data-dir")
		}
	}
	absoluteDataDir, err := filepath.Abs(dataDir)
	if err != nil {
		return "", fmt.Errorf("resolve data directory: %w", err)
	}
	return filepath.Join(absoluteDataDir, "audit"), nil
}

func terminalReader(reader io.Reader) bool {
	file, ok := reader.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func verifyAuditDir(dir string) error {
	return audit.Verify(dir)
}

func verifyWritableAuditDir(dir string, maxBytes int64) error {
	if maxBytes <= 0 {
		return errors.New("audit log quota must be positive")
	}
	var usedBytes int64
	if err := audit.Scan(dir, func(entry audit.Entry) error {
		encoded, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("encode verified audit entry: %w", err)
		}
		// Scan accepts only canonical JSON entries and requires the final newline,
		// so re-encoding each entry plus its newline reproduces the exact file size.
		usedBytes += int64(len(encoded) + 1)
		return nil
	}); err != nil {
		return err
	}
	if usedBytes >= maxBytes {
		return fmt.Errorf(
			"%w: current %d bytes, limit %d bytes",
			audit.ErrQuotaExceeded,
			usedBytes,
			maxBytes,
		)
	}
	return nil
}

func stringsUpper(value string) string {
	if value == "pass" {
		return "PASS"
	}
	return "FAIL"
}
