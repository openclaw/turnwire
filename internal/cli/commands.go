package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/openclaw/turnwire/internal/approval"
	"github.com/openclaw/turnwire/internal/audit"
	"github.com/openclaw/turnwire/internal/buildinfo"
	"github.com/openclaw/turnwire/internal/config"
	"github.com/openclaw/turnwire/internal/guard"
	"github.com/openclaw/turnwire/internal/identity"
	"github.com/openclaw/turnwire/internal/mailbox"
	"github.com/openclaw/turnwire/internal/mcpserver"
)

const probeText = "Routine scheduling note: meeting moved to 10:30 tomorrow."

func runInit(args []string, opts options, stdout io.Writer) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	var force, allowRemote bool
	var identityName, endpoint, model, apiKeyEnv, policy, policyVersion, cacheRetention string
	flags.BoolVar(&force, "force", false, "replace an existing configuration")
	flags.StringVar(&identityName, "identity", "local", "endpoint identity name")
	flags.StringVar(&endpoint, "endpoint", "", "OpenAI Responses endpoint")
	flags.StringVar(&model, "model", "", "guard model")
	flags.StringVar(&apiKeyEnv, "api-key-env", "", "API key environment variable")
	flags.StringVar(&policy, "policy", "", "channel policy")
	flags.StringVar(&policyVersion, "policy-version", "", "policy version")
	flags.StringVar(&cacheRetention, "prompt-cache-retention", "", "in_memory or 24h")
	flags.BoolVar(&allowRemote, "allow-remote", false, "permit a remote HTTPS endpoint")
	rest, help, err := parseFlags(flags, args, stdout, initHelp)
	if err != nil || help {
		return err
	}
	if err := requireNoArgs(rest); err != nil {
		return err
	}

	cfg := config.Default()
	cfg.Identity.Name = identityName
	if endpoint != "" {
		cfg.Guard.Endpoint = endpoint
	}
	if model != "" {
		cfg.Guard.Model = model
		if strings.HasPrefix(model, "gpt-5.5") && cacheRetention == "" {
			cfg.Guard.PromptCacheRetention = "24h"
		}
	}
	if apiKeyEnv != "" {
		cfg.Guard.APIKeyEnv = apiKeyEnv
	}
	if policy != "" {
		cfg.Guard.Policy = policy
	}
	if policyVersion != "" {
		cfg.Guard.PolicyVersion = policyVersion
	}
	if cacheRetention != "" {
		cfg.Guard.PromptCacheRetention = cacheRetention
	}
	if allowRemote {
		cfg.Guard.AllowRemote = true
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
	defer log.Close()
	signer, err := identity.LoadOrCreate(cfg.AuditDir, cfg.Identity.Name, true)
	if err != nil {
		return fmt.Errorf("initialize identity: %w", err)
	}
	approvalStore, err := approval.Open(cfg.AuditDir, true)
	if err != nil {
		return fmt.Errorf("initialize approvals: %w", err)
	}
	defer approvalStore.Close()
	aliasesAudit, err := log.AliasesPath(configPath)
	if err != nil {
		return fmt.Errorf("validate config path: %w", err)
	}
	if aliasesAudit {
		return errors.New("config path must not name the audit log")
	}
	guardDestination := func(parent *os.File, name string) error {
		aliasesState, guardErr := log.AliasesDirectory(parent)
		if guardErr != nil {
			return guardErr
		}
		aliasesApprovals, guardErr := approvalStore.AliasesDirectory(parent)
		if guardErr != nil {
			return guardErr
		}
		if aliasesState || aliasesApprovals {
			return errors.New("config path must be outside Turnwire state directories")
		}
		aliases, guardErr := log.AliasesEntry(parent, name)
		if guardErr != nil {
			return guardErr
		}
		if aliases {
			return errors.New("config path must not name the audit log")
		}
		return nil
	}
	if err := config.WriteGuarded(configPath, cfg, force, guardDestination); err != nil {
		return err
	}
	if !opts.quiet {
		lines := []string{
			"Initialized Turnwire\n",
			fmt.Sprintf("Identity: %s\n", strconv.Quote(cfg.Identity.Name)),
			fmt.Sprintf("Public key: %s\n", signer.PublicKey()),
			fmt.Sprintf("Config: %s\n", strconv.Quote(configPath)),
			fmt.Sprintf("Audit:  %s\n", strconv.Quote(cfg.AuditDir)),
			"Next: exchange public keys, run `turnwire peer add`, then `turnwire doctor --probe`\n",
		}
		for _, line := range lines {
			if err := writeOutput(stdout, []byte(line)); err != nil {
				return err
			}
		}
	}
	return nil
}

func runServe(ctx context.Context, args []string, opts options, stdin io.Reader, stdout, stderr io.Writer) error {
	return runServeWithGuard(ctx, args, opts, stdin, stdout, stderr, func(cfg guard.HTTPConfig) (guard.Evaluator, error) { return guard.NewHTTP(cfg) })
}

func runServeWithGuard(ctx context.Context, args []string, opts options, stdin io.Reader, stdout, stderr io.Writer, newGuard func(guard.HTTPConfig) (guard.Evaluator, error)) error {
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
	signer, err := identity.LoadOrCreate(auditDir, cfg.Identity.Name, false)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}
	approvalStore, err := approval.Open(auditDir, true)
	if err != nil {
		return fmt.Errorf("open approvals: %w", err)
	}
	defer approvalStore.Close()
	modelGuard, err := newGuard(guard.HTTPConfig{Endpoint: cfg.Guard.Endpoint, Model: cfg.Guard.Model, APIKeyEnv: cfg.Guard.APIKeyEnv, PromptCacheRetention: cfg.Guard.PromptCacheRetention})
	if err != nil {
		return err
	}
	timeout, _ := time.ParseDuration(cfg.Limits.Timeout)
	maxAge, _ := time.ParseDuration(cfg.Limits.MaxMessageAge)
	peers := make(map[string]string, len(cfg.Identity.Peers))
	for _, peer := range cfg.Identity.Peers {
		peers[peer.Name] = peer.PublicKey
	}
	service, err := mailbox.New(mailbox.Options{Audit: log, Signer: signer, Peers: peers, Guard: modelGuard, Approvals: approvalStore, Policy: cfg.Guard.Policy, PolicyVersion: cfg.Guard.PolicyVersion, MaxMessageBytes: cfg.Limits.MaxMessageBytes, Timeout: timeout, MaxMessageAge: maxAge, MaxConcurrent: cfg.Limits.MaxConcurrent})
	if err != nil {
		return err
	}
	if opts.verbose {
		fmt.Fprintln(stderr, "turnwire: serving signed mailbox MCP over stdio")
	}
	serveErr := mcpserver.Run(ctx, service, buildinfo.Current().Version, stdin, stdout, cfg.Limits.MaxMessageBytes, cfg.Limits.MaxConcurrent)
	_ = service.Shutdown(context.Background())
	if serveErr != nil {
		if ctx.Err() != nil {
			return nil
		}
		return errors.New("MCP transport failed")
	}
	return nil
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
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	var probe, asJSON bool
	flags.BoolVar(&probe, "probe", false, "probe the configured guard")
	flags.BoolVar(&asJSON, "json", false, "emit JSON")
	rest, help, err := parseFlags(flags, args, stdout, doctorHelp)
	if err != nil || help {
		return err
	}
	if err := requireNoArgs(rest); err != nil {
		return err
	}
	report := doctorReport{OK: true}
	add := func(name string, err error, ok string) {
		if err != nil {
			report.OK = false
			report.Checks = append(report.Checks, doctorCheck{Name: name, Status: "fail", Message: err.Error()})
		} else {
			report.Checks = append(report.Checks, doctorCheck{Name: name, Status: "ok", Message: ok})
		}
	}
	cfg, loadErr := config.Load(opts.configPath)
	add("config", loadErr, "valid v2 configuration")
	if loadErr == nil {
		auditDir, resolveErr := resolveAuditDir(cfg, opts.dataDir)
		add("audit_path", resolveErr, "resolved")
		if resolveErr == nil {
			add("audit", verifyWritableAuditDir(auditDir, cfg.Limits.MaxAuditBytes), "hash chain and storage valid")
			_, identityErr := identity.LoadOrCreate(auditDir, cfg.Identity.Name, false)
			add("identity", identityErr, "signing key valid")
		}
		if len(cfg.Identity.Peers) == 0 {
			add("peers", errors.New("no peer public keys configured"), "")
		} else {
			add("peers", nil, fmt.Sprintf("%d configured", len(cfg.Identity.Peers)))
		}
		if cfg.Guard.APIKeyEnv != "" {
			value, exists := os.LookupEnv(cfg.Guard.APIKeyEnv)
			if !exists || value == "" {
				add("api_key", guard.ErrMissingAPIKey, "")
			} else {
				add("api_key", nil, "configured")
			}
		}
		if probe && report.OK {
			modelGuard, guardErr := guard.NewHTTP(guard.HTTPConfig{Endpoint: cfg.Guard.Endpoint, Model: cfg.Guard.Model, APIKeyEnv: cfg.Guard.APIKeyEnv, PromptCacheRetention: cfg.Guard.PromptCacheRetention})
			if guardErr == nil {
				probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				_, guardErr = modelGuard.Evaluate(probeCtx, guard.Input{Direction: "outbound", Source: cfg.Identity.Name, Destination: cfg.Identity.Peers[0].Name, Text: probeText, Policy: cfg.Guard.Policy})
				cancel()
			}
			add("guard_probe", guardErr, "structured verdict received")
		}
	}
	if asJSON {
		if err := writeJSONOutput(stdout, report); err != nil {
			return err
		}
	} else {
		for _, check := range report.Checks {
			fmt.Fprintf(stdout, "%-14s %-4s %s\n", check.Name, strings.ToUpper(check.Status), check.Message)
		}
	}
	if !report.OK {
		return reportedError(errors.New("doctor found configuration problems"))
	}
	return nil
}

func runIdentity(args []string, opts options, stdout io.Writer) error {
	flags := flag.NewFlagSet("identity", flag.ContinueOnError)
	var asJSON bool
	flags.BoolVar(&asJSON, "json", false, "emit JSON")
	rest, help, err := parseFlags(flags, args, stdout, identityHelp)
	if err != nil || help {
		return err
	}
	if err := requireNoArgs(rest); err != nil {
		return err
	}
	cfg, err := config.Load(opts.configPath)
	if err != nil {
		return err
	}
	auditDir, err := resolveAuditDir(cfg, opts.dataDir)
	if err != nil {
		return err
	}
	signer, err := identity.LoadOrCreate(auditDir, cfg.Identity.Name, false)
	if err != nil {
		return err
	}
	value := map[string]string{"identity": cfg.Identity.Name, "public_key": signer.PublicKey()}
	if asJSON {
		return writeJSONOutput(stdout, value)
	}
	_, err = fmt.Fprintf(stdout, "Identity: %s\nPublic key: %s\n", cfg.Identity.Name, signer.PublicKey())
	return err
}

func runPeer(args []string, opts options, stdout io.Writer) error {
	if len(args) != 3 || args[0] != "add" {
		return usageError("usage: turnwire peer add NAME PUBLIC_KEY")
	}
	cfg, err := config.Load(opts.configPath)
	if err != nil {
		return err
	}
	for _, peer := range cfg.Identity.Peers {
		if peer.Name == args[1] {
			return usageError("peer %q already exists", args[1])
		}
	}
	cfg.Identity.Peers = append(cfg.Identity.Peers, config.PeerConfig{Name: args[1], PublicKey: args[2]})
	if err := cfg.Validate(); err != nil {
		return usageError("%v", err)
	}
	path := opts.configPath
	if path == "" {
		path = config.DefaultConfigPath()
	}
	if err := config.Write(path, cfg, true); err != nil {
		return err
	}
	if !opts.quiet {
		_, err = fmt.Fprintf(stdout, "Added peer %s\n", strconv.Quote(args[1]))
	}
	return err
}

func runApprove(args []string, opts options, stdin io.Reader, stdout io.Writer) error {
	flags := flag.NewFlagSet("approve", flag.ContinueOnError)
	var yes bool
	flags.BoolVar(&yes, "yes", false, "approve without interactive confirmation")
	rest, help, err := parseFlags(flags, args, stdout, approveHelp)
	if err != nil || help {
		return err
	}
	if len(rest) != 1 || !validCLIIdentifier(rest[0]) {
		return usageError("usage: turnwire approve [--yes] MESSAGE_ID")
	}
	cfg, err := config.Load(opts.configPath)
	if err != nil {
		return err
	}
	auditDir, err := resolveAuditDir(cfg, opts.dataDir)
	if err != nil {
		return err
	}
	store, err := approval.Open(auditDir, false)
	if err != nil {
		return err
	}
	defer store.Close()
	pending, err := store.Pending(rest[0])
	if err != nil {
		return err
	}
	display := fmt.Sprintf("Message: %s\nDirection: %s (%s -> %s)\nSHA-256: %s\nBody: %s\n", pending.MessageID, pending.Direction, pending.Source, pending.Destination, pending.BodySHA256, strconv.QuoteToASCII(pending.Body))
	if err := writeOutput(stdout, []byte(display)); err != nil {
		return fmt.Errorf("display pending approval: %w", err)
	}
	if !yes {
		if err := writeOutput(stdout, []byte("\nApprove this exact message? [y/N] ")); err != nil {
			return fmt.Errorf("display approval prompt: %w", err)
		}
		line, readErr := bufio.NewReader(io.LimitReader(stdin, 16)).ReadString('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		if strings.TrimSpace(strings.ToLower(line)) != "y" && strings.TrimSpace(strings.ToLower(line)) != "yes" {
			return errors.New("approval canceled")
		}
	}
	if err := store.Approve(pending.Binding(), time.Now()); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "Approved; retry the same Turnwire tool call.")
	return err
}

func runCheckpoint(args []string, opts options, stdout io.Writer) error {
	if len(args) != 0 {
		return usageError("checkpoint accepts no arguments")
	}
	cfg, err := config.Load(opts.configPath)
	if err != nil {
		return err
	}
	auditDir, err := resolveAuditDir(cfg, opts.dataDir)
	if err != nil {
		return err
	}
	log, err := audit.OpenWithQuota(auditDir, cfg.Limits.MaxAuditBytes)
	if err != nil {
		return err
	}
	defer log.Close()
	signer, err := identity.LoadOrCreate(auditDir, cfg.Identity.Name, false)
	if err != nil {
		return err
	}
	seq, head, err := log.Head()
	if err != nil {
		return err
	}
	checkpoint, err := signer.Checkpoint(seq, head, time.Now())
	if err != nil {
		return err
	}
	return writeJSONOutput(stdout, checkpoint)
}

func requireAuditCapacity(log *audit.Log) error {
	used, max, err := log.Usage()
	if err != nil {
		return err
	}
	if used >= max {
		return audit.ErrQuotaExceeded
	}
	return nil
}
func openWritableAudit(dir string, max int64) (*audit.Log, error) {
	log, err := audit.OpenWithQuota(dir, max)
	if err != nil {
		return nil, err
	}
	if err := requireAuditCapacity(log); err != nil {
		return nil, errors.Join(err, log.Close())
	}
	return log, nil
}
func writeJSONOutput(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
func resolveAuditDir(cfg config.Config, dataDir string) (string, error) {
	if dataDir != "" {
		absolute, err := filepath.Abs(dataDir)
		if err != nil {
			return "", err
		}
		return filepath.Join(filepath.Clean(absolute), "audit"), nil
	}
	if cfg.AuditDir != "" {
		return cfg.AuditDir, nil
	}
	base := config.DefaultDataDir()
	if base == "" {
		return "", errors.New("cannot determine default data directory")
	}
	return filepath.Join(base, "audit"), nil
}
func terminalReader(reader io.Reader) bool {
	file, ok := reader.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
func verifyWritableAuditDir(dir string, max int64) error {
	log, err := openWritableAudit(dir, max)
	if err != nil {
		return err
	}
	return log.Close()
}
func validCLIIdentifier(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._:-", r) {
			continue
		}
		return false
	}
	return true
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
		return writeJSONOutput(stdout, buildinfo.Current())
	}
	return writeOutput(stdout, []byte(versionLine()))
}
