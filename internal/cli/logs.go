package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"

	"github.com/openclaw/turnwire/internal/audit"
	"github.com/openclaw/turnwire/internal/config"
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
	default:
		return usageError("unknown log command %q", args[0])
	}
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
