package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
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
)

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
	timeout, _ := time.ParseDuration(cfg.Limits.Timeout)
	modelGuard, err := newGuard(guard.HTTPConfig{Endpoint: cfg.Guard.Endpoint, Model: cfg.Guard.Model, APIKeyEnv: cfg.Guard.APIKeyEnv, PromptCacheRetention: cfg.Guard.PromptCacheRetention, Timeout: timeout})
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
	if serveErr != nil {
		if ctx.Err() != nil {
			return nil
		}
		return errors.New("MCP transport failed")
	}
	return nil
}

func terminalReader(reader io.Reader) bool {
	file, ok := reader.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
