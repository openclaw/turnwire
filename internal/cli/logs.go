package cli

import (
	"encoding/json"
	"errors"
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

const maxLogReadBytes = 16 << 20

func runLog(args []string, opts options, stdout io.Writer) error {
	if len(args) == 0 {
		return usageError("usage: turnwire log <list|show|verify>")
	}
	switch args[0] {
	case "list":
		return runLogList(args[1:], opts, stdout)
	case "show":
		return runLogShow(args[1:], opts, stdout)
	case "verify":
		return runLogVerify(args[1:], opts, stdout)
	case "export":
		return runLogExport(args[1:], opts, stdout)
	default:
		return usageError("unknown log command %q", args[0])
	}
}

type exportEntry struct {
	Kind           string            `json:"kind"`
	Sequence       uint64            `json:"sequence"`
	EventID        string            `json:"event_id"`
	ExchangeID     string            `json:"exchange_id"`
	RequestID      string            `json:"request_id"`
	ConversationID string            `json:"conversation_id"`
	Type           string            `json:"type"`
	Status         string            `json:"status"`
	ErrorCode      string            `json:"error_code"`
	Timestamp      string            `json:"timestamp"`
	TextSHA256     string            `json:"text_sha256"`
	Details        map[string]string `json:"details,omitempty"`
	PreviousHash   string            `json:"previous_hash"`
	EntryHash      string            `json:"entry_hash"`
}

type exportCheckpoint struct {
	Kind       string              `json:"kind"`
	Checkpoint identity.Checkpoint `json:"checkpoint"`
}

func runLogExport(args []string, opts options, stdout io.Writer) error {
	flags := flag.NewFlagSet("log export", flag.ContinueOnError)
	var output string
	flags.StringVar(&output, "output", "", "new redacted JSONL export path")
	rest, help, err := parseFlags(flags, args, stdout, logHelp)
	if err != nil || help {
		return err
	}
	if err := requireNoArgs(rest); err != nil {
		return err
	}
	if output == "" {
		return usageError("log export requires --output")
	}
	cfg, err := config.Load(opts.configPath)
	if err != nil {
		return err
	}
	dir, err := resolveAuditDir(cfg, opts.dataDir)
	if err != nil {
		return err
	}
	log, err := audit.OpenWithQuota(dir, cfg.Limits.MaxAuditBytes)
	if err != nil {
		return err
	}
	defer log.Close()
	signer, err := identity.LoadOrCreate(dir, cfg.Identity.Name, false)
	if err != nil {
		return err
	}
	deployment, err := attestation.Measure(cfg, signer.PublicKey())
	if err != nil {
		return err
	}
	absolute, err := filepath.Abs(output)
	if err != nil {
		return fmt.Errorf("resolve audit export path: %w", err)
	}
	parent, _, err := owneronly.OpenDirectoryPathDurable(filepath.Dir(absolute), false, owneronly.DirectoryOwnerControlled, "audit export parent directory")
	if err != nil {
		return err
	}
	defer parent.Close()
	name := filepath.Base(absolute)
	aliases, err := log.AliasesEntry(parent, name)
	if err != nil {
		return err
	}
	if aliases {
		return errors.New("export path must not name the audit log")
	}
	file, err := owneronly.OpenAtNoFollow(parent, name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create audit export: %w", err)
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
	if _, err := owneronly.Validate(file, owneronly.RegularFile, "audit export"); err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	if err := log.Scan(func(entry audit.Entry) error {
		return encoder.Encode(exportEntry{
			Kind: "entry", Sequence: entry.Seq, EventID: entry.EventID, ExchangeID: entry.ExchangeID,
			RequestID: entry.RequestID, ConversationID: entry.ConversationID, Type: entry.Type,
			Status: entry.Status, ErrorCode: entry.ErrorCode, Timestamp: entry.Timestamp,
			TextSHA256: entry.TextSHA256, Details: exportDetails(entry.Details),
			PreviousHash: entry.PreviousHash, EntryHash: entry.EntryHash,
		})
	}); err != nil {
		return err
	}
	sequence, head, err := log.Head()
	if err != nil {
		return err
	}
	checkpoint, err := signer.Checkpoint(sequence, head, deployment.Digest, time.Now())
	if err != nil {
		return err
	}
	if err := encoder.Encode(exportCheckpoint{Kind: "checkpoint", Checkpoint: checkpoint}); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := parent.Sync(); err != nil {
		return err
	}
	complete = true
	if !opts.quiet {
		_, err = fmt.Fprintf(stdout, "Exported redacted audit metadata to %s\n", strconv.Quote(output))
	}
	return err
}

func exportDetails(details map[string]string) map[string]string {
	allowed := map[string]bool{
		"direction": true, "source": true, "destination": true, "message_id": true,
		"body_sha256": true, "envelope_sha256": true, "acknowledgement": true,
		"model": true, "provider_request_id": true, "provider_response_id": true,
		"decision": true, "reason_code": true, "policy_version": true,
		"identity": true, "message_count": true,
		"deployment_id": true, "deployment_sha256": true, "executable_sha256": true,
		"config_sha256": true, "policy_sha256": true, "peer_set_sha256": true,
		"identity_public_key": true, "version": true, "commit": true, "modified": true,
	}
	filtered := make(map[string]string)
	for key, value := range details {
		if allowed[key] {
			filtered[key] = value
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func runLogList(args []string, opts options, stdout io.Writer) error {
	flags := flag.NewFlagSet("log list", flag.ContinueOnError)
	var eventType, conversation string
	var limit int
	var asJSON bool
	flags.StringVar(&eventType, "type", "", "filter by event type")
	flags.StringVar(&conversation, "conversation", "", "filter by conversation ID")
	flags.IntVar(&limit, "limit", 50, "newest event count")
	flags.BoolVar(&asJSON, "json", false, "include complete event JSON")
	rest, help, err := parseFlags(flags, args, stdout, logHelp)
	if err != nil || help {
		return err
	}
	if err := requireNoArgs(rest); err != nil {
		return err
	}
	if limit < 1 || limit > 1000 {
		return usageError("--limit must be between 1 and 1000")
	}
	dir, err := auditScanTarget(opts)
	if err != nil {
		return err
	}
	entries, err := scanLogEntries(dir, eventType, conversation, limit, maxLogReadBytes)
	if err != nil {
		return err
	}
	if asJSON {
		return writeJSONOutput(stdout, entries)
	}
	for _, entry := range entries {
		peer := entry.Details["source"] + " -> " + entry.Details["destination"]
		if peer == " -> " {
			peer = "-"
		}
		if _, err := fmt.Fprintf(stdout, "%d\t%s\t%s\t%s\t%s\t%s\n", entry.Seq, entry.Timestamp, entry.Type, entry.Status, entry.ExchangeID, peer); err != nil {
			return err
		}
	}
	return nil
}

func scanLogEntries(dir, eventType, conversation string, limit, maxBytes int) ([]audit.Entry, error) {
	entries := make([]audit.Entry, 0, limit)
	ordinals := make([]int, 0, limit)
	retained := 0
	matching := 0
	lastBudgetDrop := 0
	dropOldest := func() {
		old := entries[0]
		retained -= logEntrySize(old)
		entries = entries[1:]
		ordinals = ordinals[1:]
	}
	err := audit.Scan(dir, func(entry audit.Entry) error {
		if eventType != "" && entry.Type != eventType {
			return nil
		}
		if conversation != "" && entry.ConversationID != conversation {
			return nil
		}
		matching++
		size := logEntrySize(entry)
		entries = append(entries, entry)
		ordinals = append(ordinals, matching)
		retained += size
		for len(entries) > limit {
			dropOldest()
		}
		for retained > maxBytes && len(entries) > 0 {
			lastBudgetDrop = ordinals[0]
			dropOldest()
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	windowStart := matching - limit + 1
	if windowStart < 1 {
		windowStart = 1
	}
	if lastBudgetDrop >= windowStart {
		return nil, fmt.Errorf("requested audit window exceeds the %d MiB display limit", maxBytes>>20)
	}
	return entries, nil
}

func logEntrySize(entry audit.Entry) int {
	size := len(entry.Text)
	for key, value := range entry.Details {
		size += len(key) + len(value)
	}
	return size
}

func runLogShow(args []string, opts options, stdout io.Writer) error {
	flags := flag.NewFlagSet("log show", flag.ContinueOnError)
	var asJSON bool
	flags.BoolVar(&asJSON, "json", false, "emit JSON")
	rest, help, err := parseFlags(flags, args, stdout, logHelp)
	if err != nil || help {
		return err
	}
	if len(rest) != 1 {
		return usageError("usage: turnwire log show [--json] ID")
	}
	id := rest[0]
	dir, err := auditScanTarget(opts)
	if err != nil {
		return err
	}
	entries := make([]audit.Entry, 0)
	bytes := 0
	err = audit.Scan(dir, func(entry audit.Entry) error {
		if entry.EventID != id && entry.ExchangeID != id && entry.RequestID != id && entry.Details["message_id"] != id {
			return nil
		}
		bytes += len(entry.Text)
		if bytes > maxLogReadBytes {
			return errors.New("selected audit records exceed the 16 MiB display limit")
		}
		entries = append(entries, entry)
		return nil
	})
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return errors.New("audit record not found")
	}
	if asJSON {
		return writeJSONOutput(stdout, entries)
	}
	for _, entry := range entries {
		if _, err := fmt.Fprintf(stdout, "Sequence: %d\nTime: %s\nType: %s\nStatus: %s\nEvent: %s\nMessage: %s\nText SHA-256: %s\nAudit head: %s\n", entry.Seq, entry.Timestamp, entry.Type, entry.Status, entry.EventID, entry.ExchangeID, entry.TextSHA256, entry.EntryHash); err != nil {
			return err
		}
		if entry.ErrorCode != "" {
			if _, err := fmt.Fprintf(stdout, "Error: %s\n", entry.ErrorCode); err != nil {
				return err
			}
		}
		if len(entry.Details) > 0 {
			encoded, err := json.Marshal(entry.Details)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(stdout, "Details: %s\n", encoded); err != nil {
				return err
			}
		}
		if entry.Text != "" {
			if _, err := fmt.Fprintf(stdout, "Text: %s\n", strconv.QuoteToASCII(entry.Text)); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(stdout); err != nil {
			return err
		}
	}
	return nil
}

func runLogVerify(args []string, opts options, stdout io.Writer) error {
	flags := flag.NewFlagSet("log verify", flag.ContinueOnError)
	var asJSON bool
	flags.BoolVar(&asJSON, "json", false, "emit JSON")
	rest, help, err := parseFlags(flags, args, stdout, logHelp)
	if err != nil || help {
		return err
	}
	if err := requireNoArgs(rest); err != nil {
		return err
	}
	dir, err := auditScanTarget(opts)
	if err != nil {
		return err
	}
	var count uint64
	head := ""
	if err := audit.Scan(dir, func(entry audit.Entry) error { count = entry.Seq; head = entry.EntryHash; return nil }); err != nil {
		return err
	}
	result := map[string]any{"ok": true, "entries": count, "audit_head": head}
	if asJSON {
		return writeJSONOutput(stdout, result)
	}
	_, err = fmt.Fprintf(stdout, "Audit verified: %d entries, head %s\n", count, head)
	return err
}

func auditScanTarget(opts options) (string, error) {
	cfg, err := config.Load(opts.configPath)
	if err != nil {
		return "", err
	}
	return resolveAuditDir(cfg, opts.dataDir)
}
