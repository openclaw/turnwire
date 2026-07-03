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

const (
	maxLogListRetainedBytes     = 16 << 20
	exchangeRecordOverheadBytes = 512

	logListHelp = `Usage:
  turnwire [global flags] log list [--conversation ID] [--limit N] [--json]
`
	logShowHelp = `Usage:
  turnwire [global flags] log show ID [--json]
`
	logVerifyHelp = `Usage:
  turnwire [global flags] log verify [--json]
`
)

var errLogListTooLarge = fmt.Errorf(
	"log list exceeds the %d MiB in-memory record limit; reduce --limit or filter with --conversation",
	maxLogListRetainedBytes>>20,
)

type exchangeRecord struct {
	ExchangeID     string `json:"exchange_id"`
	RequestID      string `json:"request_id"`
	ConversationID string `json:"conversation_id"`
	Status         string `json:"status"`
	ErrorCode      string `json:"error_code,omitempty"`
	CreatedAt      string `json:"created_at"`
	CompletedAt    string `json:"completed_at,omitempty"`
	Input          string `json:"input"`
	Output         string `json:"output,omitempty"`
	InputSHA256    string `json:"input_sha256"`
	OutputSHA256   string `json:"output_sha256,omitempty"`
	FirstSequence  uint64 `json:"first_sequence"`
	LastSequence   uint64 `json:"last_sequence"`
	AuditHead      string `json:"audit_head"`
}

func runLog(args []string, opts options, stdout io.Writer) error {
	if len(args) == 0 {
		if err := writeOutput(stdout, []byte(logHelp)); err != nil {
			return fmt.Errorf("write log help: %w", err)
		}
		return nil
	}
	switch args[0] {
	case "list":
		return runLogList(args[1:], opts, stdout)
	case "show":
		return runLogShow(args[1:], opts, stdout)
	case "verify":
		return runLogVerify(args[1:], opts, stdout)
	case "help", "-h", "--help":
		if len(args) != 1 {
			return usageError("usage: turnwire log help")
		}
		if err := writeOutput(stdout, []byte(logHelp)); err != nil {
			return fmt.Errorf("write log help: %w", err)
		}
		return nil
	default:
		return usageError("unknown log command %q", args[0])
	}
}

func runLogList(args []string, opts options, stdout io.Writer) error {
	flags := flag.NewFlagSet("log list", flag.ContinueOnError)
	var conversation string
	var limit int
	var asJSON bool
	flags.StringVar(&conversation, "conversation", "", "filter by conversation ID")
	flags.IntVar(&limit, "limit", 20, "maximum exchanges (16 MiB aggregate record budget)")
	flags.BoolVar(&asJSON, "json", false, "emit JSON with message bodies")
	rest, help, err := parseFlags(flags, args, stdout, logListHelp)
	if err != nil || help {
		return err
	}
	if err := requireNoArgs(rest); err != nil {
		return err
	}
	if limit < 1 || limit > 1000 {
		return usageError("--limit must be between 1 and 1000")
	}

	auditDir, err := auditScanTarget(opts)
	if err != nil {
		return err
	}
	scanner := newExchangeListScanner(conversation, limit, asJSON)
	if err := scanAuditDir(auditDir, scanner.consume); err != nil {
		return err
	}
	filtered, err := scanner.records()
	if err != nil {
		return err
	}
	if asJSON {
		if err := writeExchangeRecordsJSON(stdout, filtered); err != nil {
			return fmt.Errorf("write audit records: %w", err)
		}
		return nil
	}
	if len(filtered) == 0 {
		if err := writeOutput(stdout, []byte("No exchanges.\n")); err != nil {
			return fmt.Errorf("write audit records: %w", err)
		}
		return nil
	}
	if err := writeOutput(stdout, []byte("CREATED\tSTATUS\tEXCHANGE\tCONVERSATION\n")); err != nil {
		return fmt.Errorf("write audit records: %w", err)
	}
	for _, record := range filtered {
		line := fmt.Sprintf("%s\t%s\t%s\t%s\n",
			strconv.QuoteToGraphic(record.CreatedAt),
			strconv.QuoteToGraphic(record.Status),
			strconv.QuoteToGraphic(record.ExchangeID),
			strconv.QuoteToGraphic(record.ConversationID),
		)
		if err := writeOutput(stdout, []byte(line)); err != nil {
			return fmt.Errorf("write audit records: %w", err)
		}
	}
	return nil
}

func runLogShow(args []string, opts options, stdout io.Writer) error {
	id, asJSON, help, err := parseLogShowArgs(args)
	if err != nil {
		return err
	}
	if help {
		if err := writeOutput(stdout, []byte(logShowHelp)); err != nil {
			return fmt.Errorf("write log help: %w", err)
		}
		return nil
	}
	auditDir, err := auditScanTarget(opts)
	if err != nil {
		return err
	}
	var record *exchangeRecord
	if err := scanAuditDir(auditDir, func(entry audit.Entry) error {
		if entry.ExchangeID != id {
			return nil
		}
		if record == nil {
			record = newExchangeRecord(entry)
		}
		applyAuditEntry(record, entry)
		return nil
	}); err != nil {
		return err
	}
	if record == nil {
		return fmt.Errorf("exchange %s was not found", strconv.QuoteToGraphic(id))
	}
	if asJSON {
		if err := writeJSONOutput(stdout, record); err != nil {
			return fmt.Errorf("write audit record: %w", err)
		}
		return nil
	}
	if err := writeExchange(stdout, *record); err != nil {
		return fmt.Errorf("write audit record: %w", err)
	}
	return nil
}

func parseLogShowArgs(args []string) (id string, asJSON, help bool, err error) {
	for _, arg := range args {
		switch arg {
		case "-h", "--help":
			help = true
		case "--json":
			asJSON = true
		default:
			if len(arg) > 0 && arg[0] == '-' {
				return "", false, false, usageError("unknown flag %q", arg)
			}
			if id != "" {
				return "", false, false, usageError("unexpected argument %q", arg)
			}
			id = arg
		}
	}
	if help {
		return "", asJSON, true, nil
	}
	if id == "" {
		return "", false, false, usageError("usage: turnwire log show ID [--json]")
	}
	return id, asJSON, false, nil
}

func runLogVerify(args []string, opts options, stdout io.Writer) error {
	flags := flag.NewFlagSet("log verify", flag.ContinueOnError)
	var asJSON bool
	flags.BoolVar(&asJSON, "json", false, "emit JSON")
	rest, help, err := parseFlags(flags, args, stdout, logVerifyHelp)
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
	verifyErr := verifyAuditDir(auditDir)
	if asJSON {
		result := struct {
			OK       bool   `json:"ok"`
			AuditDir string `json:"audit_dir"`
			Error    string `json:"error,omitempty"`
		}{OK: verifyErr == nil, AuditDir: auditDir}
		if verifyErr != nil {
			result.Error = verifyErr.Error()
		}
		if err := writeJSONOutput(stdout, result); err != nil {
			return fmt.Errorf("write verification result: %w", err)
		}
	} else if verifyErr == nil {
		line := fmt.Sprintf("OK audit chain verified: %s\n", strconv.QuoteToGraphic(auditDir))
		if err := writeOutput(stdout, []byte(line)); err != nil {
			return fmt.Errorf("write verification result: %w", err)
		}
	}
	if verifyErr != nil {
		if asJSON {
			return reportedError(errors.New("audit verification failed"))
		}
		return fmt.Errorf("verify audit log: %w", verifyErr)
	}
	return nil
}

func auditScanTarget(opts options) (string, error) {
	cfg, err := config.Load(opts.configPath)
	if err != nil {
		return "", err
	}
	auditDir, err := resolveAuditDir(cfg, opts.dataDir)
	if err != nil {
		return "", err
	}
	return auditDir, nil
}

func scanAuditDir(auditDir string, visit func(audit.Entry) error) error {
	return audit.Scan(auditDir, visit)
}

type exchangeListScanner struct {
	conversation            string
	limit                   int
	includeBodies           bool
	maxRetainedBytes        int
	retainedBytes           int
	totalRequests           uint64
	maxBudgetEvictedOrdinal uint64
	start                   int
	count                   int
	retained                []*retainedExchange
	retainedByID            map[string]*retainedExchange
}

type retainedExchange struct {
	ordinal uint64
	bytes   int
	record  exchangeRecord
}

func newExchangeListScanner(conversation string, limit int, includeBodies bool) *exchangeListScanner {
	scanner := &exchangeListScanner{
		conversation:  conversation,
		limit:         limit,
		includeBodies: includeBodies,
		retained:      make([]*retainedExchange, limit),
		retainedByID:  make(map[string]*retainedExchange, limit),
	}
	scanner.maxRetainedBytes = maxLogListRetainedBytes
	return scanner
}

func (s *exchangeListScanner) consume(entry audit.Entry) error {
	if entry.Type != "request_received" {
		if retained := s.retainedByID[entry.ExchangeID]; retained != nil {
			s.applyRetainedEntry(retained, entry)
		}
		return nil
	}
	if s.conversation != "" && entry.ConversationID != s.conversation {
		return nil
	}
	if current := s.retainedByID[entry.ExchangeID]; current != nil {
		s.applyRetainedEntry(current, entry)
		return nil
	}
	record := newExchangeListRecord(entry, s.includeBodies)
	applyExchangeListEntry(record, entry, s.includeBodies)
	s.totalRequests++
	retained := &retainedExchange{
		ordinal: s.totalRequests,
		bytes:   retainedExchangeRecordBytes(record),
		record:  *record,
	}
	if s.count == s.limit {
		s.evictOldest(false)
	}
	s.appendRetained(retained)
	s.enforceRetentionBudget()
	return nil
}

func (s *exchangeListScanner) applyRetainedEntry(retained *retainedExchange, entry audit.Entry) {
	updated := retained.record
	applyExchangeListEntry(&updated, entry, s.includeBodies)
	afterBytes := retainedExchangeRecordBytes(&updated)
	s.retainedBytes += afterBytes - retained.bytes
	retained.record = updated
	retained.bytes = afterBytes
	s.enforceRetentionBudget()
}

func (s *exchangeListScanner) appendRetained(retained *retainedExchange) {
	position := (s.start + s.count) % s.limit
	s.retained[position] = retained
	s.retainedByID[retained.record.ExchangeID] = retained
	s.retainedBytes += retained.bytes
	s.count++
}

func (s *exchangeListScanner) enforceRetentionBudget() {
	// Retain the largest newest suffix that fits. Whether a discarded record was
	// actually requested cannot be known until the final matching ordinal is seen.
	for s.count != 0 && s.retainedBytes > s.maxRetainedBytes {
		s.evictOldest(true)
	}
}

func (s *exchangeListScanner) evictOldest(forBudget bool) {
	retained := s.retained[s.start]
	s.retained[s.start] = nil
	s.start = (s.start + 1) % s.limit
	s.count--
	s.retainedBytes -= retained.bytes
	if current := s.retainedByID[retained.record.ExchangeID]; current == retained {
		delete(s.retainedByID, retained.record.ExchangeID)
	}
	if forBudget && retained.ordinal > s.maxBudgetEvictedOrdinal {
		s.maxBudgetEvictedOrdinal = retained.ordinal
	}
}

func (s *exchangeListScanner) records() ([]exchangeRecord, error) {
	finalWindowStart := uint64(1)
	if s.totalRequests > uint64(s.limit) {
		finalWindowStart = s.totalRequests - uint64(s.limit) + 1
	}
	// Limit-driven evictions are always older than the requested window. A
	// budget-driven eviction is an error only when it removed part of that window.
	if s.maxBudgetEvictedOrdinal >= finalWindowStart {
		return nil, errLogListTooLarge
	}
	records := make([]exchangeRecord, s.count)
	for i := range records {
		position := (s.start + s.count - 1 - i) % s.limit
		records[i] = s.retained[position].record
	}
	return records, nil
}

func newExchangeListRecord(entry audit.Entry, includeBodies bool) *exchangeRecord {
	record := &exchangeRecord{
		ExchangeID:     entry.ExchangeID,
		ConversationID: entry.ConversationID,
		Status:         "pending",
	}
	if includeBodies {
		record.RequestID = entry.RequestID
		record.FirstSequence = entry.Seq
	}
	return record
}

func applyExchangeListEntry(record *exchangeRecord, entry audit.Entry, includeBodies bool) {
	if includeBodies {
		applyAuditEntry(record, entry)
		return
	}
	switch entry.Type {
	case "request_received":
		record.CreatedAt = entry.Timestamp
	case "reply_committed":
		record.Status = "succeeded"
	case "run_failed":
		record.Status = "failed"
	}
}

func retainedExchangeRecordBytes(record *exchangeRecord) int {
	return exchangeRecordOverheadBytes +
		len(record.ExchangeID) +
		len(record.RequestID) +
		len(record.ConversationID) +
		len(record.Status) +
		len(record.ErrorCode) +
		len(record.CreatedAt) +
		len(record.CompletedAt) +
		len(record.Input) +
		len(record.Output) +
		len(record.InputSHA256) +
		len(record.OutputSHA256) +
		len(record.AuditHead)
}

func writeExchangeRecordsJSON(w io.Writer, records []exchangeRecord) error {
	if err := writeOutput(w, []byte{'['}); err != nil {
		return err
	}
	for i := range records {
		encoded, err := json.Marshal(records[i])
		if err != nil {
			return err
		}
		if i != 0 {
			if err := writeOutput(w, []byte{','}); err != nil {
				return err
			}
		}
		if err := writeOutput(w, encoded); err != nil {
			return err
		}
	}
	return writeOutput(w, []byte{']', '\n'})
}

func newExchangeRecord(entry audit.Entry) *exchangeRecord {
	return &exchangeRecord{
		ExchangeID:     entry.ExchangeID,
		RequestID:      entry.RequestID,
		ConversationID: entry.ConversationID,
		Status:         "pending",
		FirstSequence:  entry.Seq,
	}
}

func applyAuditEntry(record *exchangeRecord, entry audit.Entry) {
	record.LastSequence = entry.Seq
	record.AuditHead = entry.EntryHash
	switch entry.Type {
	case "request_received":
		record.CreatedAt = entry.Timestamp
		record.Input = entry.Text
		record.InputSHA256 = entry.TextSHA256
	case "reply_committed":
		record.Status = "succeeded"
		record.CompletedAt = entry.Timestamp
		record.Output = entry.Text
		record.OutputSHA256 = entry.TextSHA256
	case "run_failed":
		record.Status = "failed"
		record.CompletedAt = entry.Timestamp
		record.ErrorCode = entry.ErrorCode
	}
}

func writeExchange(w io.Writer, record exchangeRecord) error {
	if err := writeExchangeLine(w, "Exchange:     %s\n", strconv.QuoteToGraphic(record.ExchangeID)); err != nil {
		return err
	}
	if err := writeExchangeLine(w, "Request:      %s\n", strconv.QuoteToGraphic(record.RequestID)); err != nil {
		return err
	}
	if err := writeExchangeLine(w, "Conversation: %s\n", strconv.QuoteToGraphic(record.ConversationID)); err != nil {
		return err
	}
	if err := writeExchangeLine(w, "Status:       %s\n", strconv.QuoteToGraphic(record.Status)); err != nil {
		return err
	}
	if err := writeExchangeLine(w, "Created:      %s\n", strconv.QuoteToGraphic(record.CreatedAt)); err != nil {
		return err
	}
	if record.CompletedAt != "" {
		if err := writeExchangeLine(w, "Completed:    %s\n", strconv.QuoteToGraphic(record.CompletedAt)); err != nil {
			return err
		}
	}
	if record.ErrorCode != "" {
		if err := writeExchangeLine(w, "Error:        %s\n", strconv.QuoteToGraphic(record.ErrorCode)); err != nil {
			return err
		}
	}
	if err := writeExchangeLine(w, "Input:        %s\n", strconv.QuoteToGraphic(record.Input)); err != nil {
		return err
	}
	return writeExchangeLine(w, "Output:       %s\n", strconv.QuoteToGraphic(record.Output))
}

func writeExchangeLine(w io.Writer, format, value string) error {
	line := fmt.Sprintf(format, value)
	if err := writeOutput(w, []byte(line)); err != nil {
		return err
	}
	return nil
}
