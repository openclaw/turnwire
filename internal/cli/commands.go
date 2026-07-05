package cli

import (
	"bufio"
	"bytes"
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
	"github.com/openclaw/turnwire/internal/attestation"
	"github.com/openclaw/turnwire/internal/audit"
	"github.com/openclaw/turnwire/internal/buildinfo"
	"github.com/openclaw/turnwire/internal/config"
	"github.com/openclaw/turnwire/internal/guard"
	"github.com/openclaw/turnwire/internal/identity"
	"github.com/openclaw/turnwire/internal/mailbox"
	"github.com/openclaw/turnwire/internal/mcpserver"
	"github.com/openclaw/turnwire/internal/owneronly"
)

const probeText = "Routine scheduling note: meeting moved to 10:30 tomorrow."

func runInit(args []string, opts options, stdout io.Writer) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	var force, allowRemote bool
	var identityName, deploymentID, endpoint, model, apiKeyEnv, policy, policyVersion, cacheRetention string
	flags.BoolVar(&force, "force", false, "replace an existing configuration")
	flags.StringVar(&identityName, "identity", "local", "endpoint identity name")
	flags.StringVar(&deploymentID, "deployment-id", "", "tunnel or app deployment identity")
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
	cfg.Deployment.ID = identityName
	if deploymentID != "" {
		cfg.Deployment.ID = deploymentID
	}
	if endpoint != "" {
		cfg.Guard.Endpoint = endpoint
	}
	if model != "" {
		cfg.Guard.Model = model
		if model == "gpt-5.5-2026-04-23" && cacheRetention == "" {
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
	deployment, err := attestation.Measure(cfg, signer.PublicKey())
	if err != nil {
		return fmt.Errorf("measure deployment: %w", err)
	}
	modified := "unknown"
	if deployment.Modified != nil {
		modified = strconv.FormatBool(*deployment.Modified)
	}
	if _, err := log.Append(audit.Event{
		EventID: "deployment:" + deployment.Digest, ExchangeID: "deployment:" + deployment.DeploymentID,
		RequestID: "startup:" + deployment.Digest, ConversationID: "deployment:" + deployment.DeploymentID,
		Type: "service_started", Status: "attested",
		Details: map[string]string{
			"deployment_id": deployment.DeploymentID, "deployment_sha256": deployment.Digest,
			"executable_sha256": deployment.ExecutableSHA256, "config_sha256": deployment.ConfigSHA256,
			"policy_sha256": deployment.PolicySHA256, "peer_set_sha256": deployment.PeerSetSHA256,
			"identity_public_key": deployment.PublicKey, "version": deployment.Version,
			"commit": deployment.Commit, "modified": modified,
		},
	}); err != nil {
		return fmt.Errorf("record deployment attestation: %w", err)
	}
	timeout, _ := time.ParseDuration(cfg.Limits.Timeout)
	maxAge, _ := time.ParseDuration(cfg.Limits.MaxMessageAge)
	peers := make(map[string]string, len(cfg.Identity.Peers))
	for _, peer := range cfg.Identity.Peers {
		peers[peer.Name] = peer.PublicKey
	}
	service, err := mailbox.New(mailbox.Options{
		Audit: log, Signer: signer, Peers: peers, Guard: modelGuard, Approvals: approvalStore,
		Policy: cfg.Guard.Policy, PolicyVersion: cfg.Guard.PolicyVersion,
		DeploymentSHA256: deployment.Digest,
		MaxMessageBytes:  cfg.Limits.MaxMessageBytes, Timeout: timeout, MaxMessageAge: maxAge,
		MaxConcurrent: cfg.Limits.MaxConcurrent, MaxRequestsPerMinute: cfg.Limits.MaxRequestsPerMinute,
		MaxGuardCallsPerHour: cfg.Limits.MaxGuardCallsPerHour,
	})
	if err != nil {
		return err
	}
	if opts.verbose {
		fmt.Fprintln(stderr, "turnwire: serving signed mailbox MCP over stdio")
	}
	serveErr := mcpserver.Run(ctx, service, buildinfo.Current().Version, stdin, stdout, auditDir, cfg.Limits.MaxMessageBytes, cfg.Limits.MaxConcurrent, cfg.Limits.MaxRequestsPerMinute)
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
	add("config", loadErr, "valid configuration")
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
	if len(args) == 0 {
		return usageError("usage: turnwire identity <show|rotate|revoke>")
	}
	switch args[0] {
	case "show":
		return runIdentityShow(args[1:], opts, stdout)
	case "rotate":
		return runIdentityRotate(args[1:], opts, stdout)
	case "revoke":
		return runIdentityRevoke(args[1:], opts, stdout)
	default:
		return usageError("unknown identity command %q", args[0])
	}
}

func runIdentityShow(args []string, opts options, stdout io.Writer) error {
	flags := flag.NewFlagSet("identity show", flag.ContinueOnError)
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

func runIdentityRotate(args []string, opts options, stdout io.Writer) error {
	flags := flag.NewFlagSet("identity rotate", flag.ContinueOnError)
	var force bool
	var output string
	flags.BoolVar(&force, "force", false, "confirm private-key replacement")
	flags.StringVar(&output, "output", "", "new owner-only transition certificate path")
	rest, help, err := parseFlags(flags, args, stdout, identityHelp)
	if err != nil || help {
		return err
	}
	if err := requireNoArgs(rest); err != nil {
		return err
	}
	if !force {
		return usageError("identity rotate requires --force")
	}
	if output == "" {
		return usageError("identity rotate requires --output")
	}
	cfg, auditDir, log, err := openIdentityOperation(opts)
	if err != nil {
		return err
	}
	defer log.Close()
	plan, err := identity.PrepareRotation(auditDir, cfg.Identity.Name, time.Now())
	if err != nil {
		return err
	}
	rotation := plan.Certificate()
	if err := writeLifecycleCertificate(output, rotation); err != nil {
		return err
	}
	if _, err := log.Append(audit.Event{
		EventID: "identity-rotation-prepared:" + rotation.NewPublicKey, ExchangeID: "identity:" + cfg.Identity.Name,
		RequestID: "identity-rotation", ConversationID: "deployment:" + cfg.Deployment.ID,
		Type: "identity_rotation_prepared", Status: "prepared",
		Details: map[string]string{
			"previous_public_key": rotation.PreviousPublicKey, "new_public_key": rotation.NewPublicKey,
			"created_at": rotation.CreatedAt, "previous_signature": rotation.PreviousSignature,
			"new_signature": rotation.NewSignature,
		},
	}); err != nil {
		return fmt.Errorf("record prepared identity rotation: %w", err)
	}
	if err := plan.Commit(); err != nil {
		return err
	}
	if _, err := log.Append(audit.Event{
		EventID: "identity-rotation-completed:" + rotation.NewPublicKey, ExchangeID: "identity:" + cfg.Identity.Name,
		RequestID: "identity-rotation", ConversationID: "deployment:" + cfg.Deployment.ID,
		Type: "identity_rotated", Status: "completed",
		Details: map[string]string{"previous_public_key": rotation.PreviousPublicKey, "new_public_key": rotation.NewPublicKey},
	}); err != nil {
		return fmt.Errorf("record completed identity rotation: %w", err)
	}
	if !opts.quiet {
		_, err = fmt.Fprintf(stdout, "Rotated identity; certificate: %s\n", strconv.Quote(output))
	}
	return err
}

func runIdentityRevoke(args []string, opts options, stdout io.Writer) error {
	flags := flag.NewFlagSet("identity revoke", flag.ContinueOnError)
	var force bool
	var output string
	flags.BoolVar(&force, "force", false, "confirm private-key destruction")
	flags.StringVar(&output, "output", "", "new owner-only revocation certificate path")
	rest, help, err := parseFlags(flags, args, stdout, identityHelp)
	if err != nil || help {
		return err
	}
	if err := requireNoArgs(rest); err != nil {
		return err
	}
	if !force {
		return usageError("identity revoke requires --force")
	}
	if output == "" {
		return usageError("identity revoke requires --output")
	}
	cfg, auditDir, log, err := openIdentityOperation(opts)
	if err != nil {
		return err
	}
	defer log.Close()
	plan, err := identity.PrepareRevocation(auditDir, cfg.Identity.Name, time.Now())
	if err != nil {
		return err
	}
	revocation := plan.Certificate()
	if _, err := log.Append(audit.Event{
		EventID: "identity-revocation-prepared:" + revocation.PublicKey, ExchangeID: "identity:" + cfg.Identity.Name,
		RequestID: "identity-revocation", ConversationID: "deployment:" + cfg.Deployment.ID,
		Type: "identity_revocation_prepared", Status: "prepared",
		Details: map[string]string{
			"public_key": revocation.PublicKey, "created_at": revocation.CreatedAt,
			"signature": revocation.Signature,
		},
	}); err != nil {
		return fmt.Errorf("record prepared identity revocation: %w", err)
	}
	sequence, head, err := log.Head()
	if err != nil {
		return err
	}
	signer, err := identity.LoadOrCreate(auditDir, cfg.Identity.Name, false)
	if err != nil {
		return err
	}
	deployment, err := attestation.Measure(cfg, signer.PublicKey())
	if err != nil {
		return err
	}
	checkpoint, err := signer.Checkpoint(sequence, head, deployment.Digest, time.Now())
	if err != nil {
		return err
	}
	bundle := struct {
		Revocation identity.Revocation `json:"revocation"`
		Checkpoint identity.Checkpoint `json:"checkpoint"`
	}{Revocation: revocation, Checkpoint: checkpoint}
	if err := writeLifecycleCertificate(output, bundle); err != nil {
		return err
	}
	if err := plan.Commit(); err != nil {
		return err
	}
	if _, err := log.Append(audit.Event{
		EventID: "identity-revocation-completed:" + revocation.PublicKey, ExchangeID: "identity:" + cfg.Identity.Name,
		RequestID: "identity-revocation", ConversationID: "deployment:" + cfg.Deployment.ID,
		Type: "identity_revoked", Status: "completed",
		Details: map[string]string{"public_key": revocation.PublicKey},
	}); err != nil {
		return fmt.Errorf("record completed identity revocation: %w", err)
	}
	if !opts.quiet {
		_, err = fmt.Fprintf(stdout, "Revoked identity; certificate: %s\n", strconv.Quote(output))
	}
	return err
}

func writeLifecycleCertificate(path string, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode identity certificate: %w", err)
	}
	encoded = append(encoded, '\n')
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve identity certificate path: %w", err)
	}
	parent, _, err := owneronly.OpenDirectoryPathDurable(filepath.Dir(absolute), false, owneronly.DirectoryOwnerControlled, "certificate parent directory")
	if err != nil {
		return err
	}
	defer parent.Close()
	name := filepath.Base(absolute)
	file, err := owneronly.OpenAtNoFollow(parent, name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create identity certificate: %w", err)
	}
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = owneronly.UnlinkAt(parent, name)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := owneronly.Validate(file, owneronly.RegularFile, "identity certificate"); err != nil {
		return err
	}
	if _, err := io.Copy(file, bytes.NewReader(encoded)); err != nil {
		return fmt.Errorf("write identity certificate: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync identity certificate: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close identity certificate: %w", err)
	}
	if err := parent.Sync(); err != nil {
		return fmt.Errorf("sync identity certificate directory: %w", err)
	}
	complete = true
	return nil
}

func openIdentityOperation(opts options) (config.Config, string, *audit.Log, error) {
	cfg, err := config.Load(opts.configPath)
	if err != nil {
		return config.Config{}, "", nil, err
	}
	auditDir, err := resolveAuditDir(cfg, opts.dataDir)
	if err != nil {
		return config.Config{}, "", nil, err
	}
	log, err := openWritableAudit(auditDir, cfg.Limits.MaxAuditBytes)
	if err != nil {
		return config.Config{}, "", nil, fmt.Errorf("lock endpoint state: %w", err)
	}
	return cfg, auditDir, log, nil
}

func runPeer(args []string, opts options, stdout io.Writer) error {
	if len(args) == 0 {
		return usageError("usage: turnwire peer <add|rotate|remove>")
	}
	switch args[0] {
	case "add":
		return runPeerAdd(args[1:], opts, stdout)
	case "rotate":
		return runPeerRotate(args[1:], opts, stdout)
	case "remove":
		return runPeerRemove(args[1:], opts, stdout)
	default:
		return usageError("unknown peer command %q", args[0])
	}
}

func runPeerAdd(args []string, opts options, stdout io.Writer) error {
	if len(args) != 2 {
		return usageError("usage: turnwire peer add NAME PUBLIC_KEY")
	}
	cfg, err := config.Load(opts.configPath)
	if err != nil {
		return err
	}
	for _, peer := range cfg.Identity.Peers {
		if peer.Name == args[0] {
			return usageError("peer %q already exists", args[0])
		}
	}
	cfg.Identity.Peers = append(cfg.Identity.Peers, config.PeerConfig{Name: args[0], PublicKey: args[1]})
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
		_, err = fmt.Fprintf(stdout, "Added peer %s\n", strconv.Quote(args[0]))
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
	deployment, err := attestation.Measure(cfg, signer.PublicKey())
	if err != nil {
		return err
	}
	checkpoint, err := signer.Checkpoint(seq, head, deployment.Digest, time.Now())
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

func runPeerRotate(args []string, opts options, stdout io.Writer) error {
	if len(args) != 2 {
		return usageError("usage: turnwire peer rotate NAME ROTATION_FILE")
	}
	file, err := os.Open(args[1])
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 64<<10))
	decoder.DisallowUnknownFields()
	var rotation identity.Rotation
	if err := decoder.Decode(&rotation); err != nil {
		return fmt.Errorf("decode identity rotation: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("decode identity rotation: multiple JSON values")
		}
		return fmt.Errorf("decode identity rotation: %w", err)
	}
	cfg, err := config.Load(opts.configPath)
	if err != nil {
		return err
	}
	found := false
	for index := range cfg.Identity.Peers {
		if cfg.Identity.Peers[index].Name != args[0] {
			continue
		}
		if err := identity.VerifyRotation(rotation, args[0], cfg.Identity.Peers[index].PublicKey); err != nil {
			return err
		}
		cfg.Identity.Peers[index].PublicKey = rotation.NewPublicKey
		found = true
		break
	}
	if !found {
		return usageError("peer %q is not configured", args[0])
	}
	if err := writeUpdatedConfig(opts, cfg); err != nil {
		return err
	}
	if !opts.quiet {
		_, err = fmt.Fprintf(stdout, "Rotated peer %s to %s\n", args[0], rotation.NewPublicKey)
	}
	return err
}

func runPeerRemove(args []string, opts options, stdout io.Writer) error {
	flags := flag.NewFlagSet("peer remove", flag.ContinueOnError)
	var force bool
	flags.BoolVar(&force, "force", false, "confirm peer removal")
	rest, help, err := parseFlags(flags, args, stdout, peerHelp)
	if err != nil || help {
		return err
	}
	if len(rest) != 1 {
		return usageError("usage: turnwire peer remove --force NAME")
	}
	if !force {
		return usageError("peer remove requires --force")
	}
	cfg, err := config.Load(opts.configPath)
	if err != nil {
		return err
	}
	peers := cfg.Identity.Peers[:0]
	found := false
	for _, peer := range cfg.Identity.Peers {
		if peer.Name == rest[0] {
			found = true
			continue
		}
		peers = append(peers, peer)
	}
	if !found {
		return usageError("peer %q is not configured", rest[0])
	}
	cfg.Identity.Peers = peers
	if err := writeUpdatedConfig(opts, cfg); err != nil {
		return err
	}
	if !opts.quiet {
		_, err = fmt.Fprintf(stdout, "Removed peer %s\n", rest[0])
	}
	return err
}

func writeUpdatedConfig(opts options, cfg config.Config) error {
	path := opts.configPath
	if path == "" {
		path = config.DefaultConfigPath()
	}
	return config.Write(path, cfg, true)
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
