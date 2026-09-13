package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/openclaw/turnwire/internal/attestation"
	"github.com/openclaw/turnwire/internal/audit"
	"github.com/openclaw/turnwire/internal/config"
	"github.com/openclaw/turnwire/internal/identity"
	"github.com/openclaw/turnwire/internal/owneronly"
)

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
