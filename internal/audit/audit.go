// Package audit provides a small append-only, tamper-evident event log.
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/openclaw/turnwire/internal/owneronly"
)

const (
	// FileName is the fixed file name used inside an audit directory.
	FileName = "audit.jsonl"
	// DefaultMaxBytes bounds the audit log when callers do not select a
	// deployment-specific quota.
	DefaultMaxBytes int64 = 256 << 20

	genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"
	maxLineSize = 16 << 20
)

var (
	ErrClosed              = errors.New("audit log is closed")
	ErrLocked              = errors.New("audit log is already open by another writer")
	ErrQuotaExceeded       = errors.New("audit log quota exceeded")
	ErrUnsupportedPlatform = errors.New("secure audit storage is unsupported on this platform")
	ErrUncertainDurability = errors.New("audit durability is uncertain; close and reopen the log")
)

type auditIO struct {
	writeFile     func(*os.File, []byte) error
	syncFile      func(*os.File) error
	syncDirectory func(*os.File) error
}

func defaultAuditIO() auditIO {
	return auditIO{
		writeFile:     func(file *os.File, data []byte) error { return writeAll(file, data) },
		syncFile:      func(file *os.File) error { return file.Sync() },
		syncDirectory: func(directory *os.File) error { return directory.Sync() },
	}
}

// Event contains the caller-controlled fields for a new audit entry. Timestamp,
// sequence number, hashes, and the previous-chain link are assigned by Append.
type Event struct {
	EventID        string
	ExchangeID     string
	RequestID      string
	ConversationID string
	Type           string
	Status         string
	ErrorCode      string
	Text           string
	Details        map[string]string
}

// Entry is the durable representation of an audit event.
type Entry struct {
	Seq            uint64            `json:"seq"`
	EventID        string            `json:"event_id"`
	ExchangeID     string            `json:"exchange_id"`
	RequestID      string            `json:"request_id"`
	ConversationID string            `json:"conversation_id"`
	Type           string            `json:"type"`
	Status         string            `json:"status"`
	ErrorCode      string            `json:"error_code"`
	Timestamp      string            `json:"timestamp"`
	Text           string            `json:"text"`
	TextSHA256     string            `json:"text_sha256"`
	Details        map[string]string `json:"details,omitempty"`
	PreviousHash   string            `json:"previous_hash"`
	EntryHash      string            `json:"entry_hash"`
}

// EntryReference identifies one verified entry in the append-only log without
// retaining its text in memory. References are valid for the lifetime of the
// log: successful appends never move existing bytes.
type EntryReference struct {
	offset    int64
	length    int64
	seq       uint64
	entryHash string
}

type hashableEntry struct {
	Seq            uint64            `json:"seq"`
	EventID        string            `json:"event_id"`
	ExchangeID     string            `json:"exchange_id"`
	RequestID      string            `json:"request_id"`
	ConversationID string            `json:"conversation_id"`
	Type           string            `json:"type"`
	Status         string            `json:"status"`
	ErrorCode      string            `json:"error_code"`
	Timestamp      string            `json:"timestamp"`
	Text           string            `json:"text"`
	TextSHA256     string            `json:"text_sha256"`
	Details        map[string]string `json:"details,omitempty"`
	PreviousHash   string            `json:"previous_hash"`
}

// Log serializes appends from all goroutines and holds an exclusive OS lock for
// its lifetime so another process cannot write the same chain concurrently.
type Log struct {
	mu            sync.Mutex
	file          *os.File
	path          string
	directoryInfo os.FileInfo
	seq           uint64
	head          string
	size          int64
	maxBytes      int64
	failed        error
	io            auditIO
}

// Open creates or opens an audit directory, enforces restrictive permissions,
// and verifies the complete existing chain before allowing another append.
func Open(dir string) (*Log, error) {
	return OpenWithQuota(dir, DefaultMaxBytes)
}

// OpenWithQuota opens an audit log with a maximum encoded size. An existing
// verified log may be opened above the selected quota for inspection and
// recovery, but no new entry is admitted until it fits within the quota.
func OpenWithQuota(dir string, maxBytes int64) (*Log, error) {
	return openWithQuotaAndIO(dir, maxBytes, defaultAuditIO())
}

func openWithIO(dir string, ioOps auditIO) (*Log, error) {
	return openWithQuotaAndIO(dir, DefaultMaxBytes, ioOps)
}

func openWithQuotaAndIO(dir string, maxBytes int64, ioOps auditIO) (*Log, error) {
	if !secureStorageSupported() {
		// Fail closed where descriptor-relative, owner-only ACL validation is
		// unavailable. Windows in particular cannot be secured with os.Chmod.
		return nil, ErrUnsupportedPlatform
	}
	if dir == "" {
		return nil, errors.New("audit directory is required")
	}
	if maxBytes <= 0 {
		return nil, errors.New("audit log quota must be positive")
	}
	directory, _, err := openAuditDirectory(dir, true)
	if err != nil {
		return nil, err
	}
	directoryOpen := true
	defer func() {
		if directoryOpen {
			_ = directory.Close()
		}
	}()

	path := filepath.Join(dir, FileName)
	file, _, err := openAuditFile(directory, true, true)
	if err != nil {
		return nil, err
	}
	if err := lockFile(file); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock audit file: %w", err)
	}
	closeOnError := func(openErr error) (*Log, error) {
		_ = unlockFile(file)
		_ = file.Close()
		return nil, openErr
	}
	// Flush both the file metadata and its directory entry before any append can
	// be reported durable. This also completes recovery after a prior interrupted
	// initialization.
	if err := ioOps.syncFile(file); err != nil {
		return closeOnError(fmt.Errorf("sync audit file metadata: %w", err))
	}
	// Always flush the held directory before serving. A prior process may have
	// created or renamed the entry but failed its directory sync; existence in
	// the page cache is not durability proof.
	if err := ioOps.syncDirectory(directory); err != nil {
		return closeOnError(fmt.Errorf("sync audit directory: %w", err))
	}
	directoryInfo, err := directory.Stat()
	if err != nil {
		return closeOnError(fmt.Errorf("inspect audit directory: %w", err))
	}
	if err := directory.Close(); err != nil {
		return closeOnError(fmt.Errorf("close audit directory: %w", err))
	}
	directoryOpen = false

	summary, err := scanAndVerify(file, nil)
	if err != nil {
		return closeOnError(fmt.Errorf("verify audit log: %w", err))
	}
	log := &Log{
		file:          file,
		path:          path,
		directoryInfo: directoryInfo,
		seq:           summary.seq,
		head:          summary.head,
		size:          summary.size,
		maxBytes:      maxBytes,
		io:            ioOps,
	}
	return log, nil
}

func secureStorageSupported() bool {
	return runtime.GOOS == "darwin" || runtime.GOOS == "linux"
}

func openAuditDirectory(dir string, create bool) (*os.File, bool, error) {
	return owneronly.OpenDirectoryPathDurable(
		dir,
		create,
		owneronly.DirectoryOwnerOnly,
		"audit directory",
	)
}

func openAuditFile(directory *os.File, writable, create bool) (*os.File, bool, error) {
	flags := os.O_RDONLY
	if writable {
		flags = os.O_RDWR | os.O_APPEND
	}
	file, err := owneronly.OpenAtNoFollow(directory, FileName, flags, 0)
	created := false
	if errors.Is(err, os.ErrNotExist) && create {
		file, err = owneronly.OpenAtNoFollow(
			directory,
			FileName,
			flags|os.O_CREATE|os.O_EXCL,
			0o600,
		)
		created = err == nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("open audit file: %w", err)
	}
	closeOnError := func(openErr error) (*os.File, bool, error) {
		_ = file.Close()
		return nil, false, openErr
	}
	if created {
		if err := file.Chmod(0o600); err != nil {
			return closeOnError(fmt.Errorf("secure audit file: %w", err))
		}
	}
	if _, err := owneronly.Validate(file, owneronly.RegularFile, "audit file"); err != nil {
		return closeOnError(err)
	}
	return file, created, nil
}

func openExistingAudit(dir string) (*os.File, *os.File, error) {
	if !secureStorageSupported() {
		return nil, nil, ErrUnsupportedPlatform
	}
	directory, _, err := openAuditDirectory(dir, false)
	if err != nil {
		return nil, nil, err
	}
	file, _, err := openAuditFile(directory, true, false)
	if err != nil {
		_ = directory.Close()
		return nil, nil, err
	}
	closeOnError := func(openErr error) (*os.File, *os.File, error) {
		_ = unlockFile(file)
		_ = file.Close()
		_ = directory.Close()
		return nil, nil, openErr
	}
	// A free-path read is also a recovery open. The exclusive lock prevents it
	// from observing a live writer's uncertain page cache; syncing both handles
	// establishes durability before the caller verifies the chain.
	if err := lockFile(file); err != nil {
		_ = file.Close()
		_ = directory.Close()
		return nil, nil, fmt.Errorf("lock audit file for recovery read: %w", err)
	}
	if err := file.Sync(); err != nil {
		return closeOnError(fmt.Errorf("sync audit file for recovery read: %w", err))
	}
	if err := directory.Sync(); err != nil {
		return closeOnError(fmt.Errorf("sync audit directory for recovery read: %w", err))
	}
	return directory, file, nil
}

func closeExistingAudit(directory, file *os.File) {
	_ = unlockFile(file)
	_ = file.Close()
	_ = directory.Close()
}

// Path returns the audit JSONL path.
func (l *Log) Path() string {
	return l.path
}

// Usage returns the verified encoded size and configured quota. A clean quota
// rejection leaves Usage and the read-only log operations available.
func (l *Log) Usage() (usedBytes, maxBytes int64, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.readyLocked(); err != nil {
		return 0, 0, err
	}
	return l.size, l.maxBytes, nil
}

// AliasesPath performs a best-effort path preflight for clear CLI diagnostics.
// It is not an authorization boundary: callers that will mutate the path must
// use AliasesEntry with the exact parent descriptor retained for that mutation.
func (l *Log) AliasesPath(path string) (bool, error) {
	if path == "" {
		return false, errors.New("candidate path is required")
	}

	l.mu.Lock()
	if err := l.readyLocked(); err != nil {
		l.mu.Unlock()
		return false, err
	}
	auditInfo, err := l.file.Stat()
	if err != nil {
		l.mu.Unlock()
		return false, fmt.Errorf("inspect audit file: %w", err)
	}
	candidateInfo, statErr := os.Stat(path)
	if statErr == nil && os.SameFile(auditInfo, candidateInfo) {
		l.mu.Unlock()
		return true, nil
	}
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		l.mu.Unlock()
		return false, fmt.Errorf("inspect candidate path: %w", statErr)
	}
	l.mu.Unlock()

	parentPath, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return false, fmt.Errorf("resolve candidate parent directory: %w", err)
	}
	parent, _, err := owneronly.OpenDirectoryPath(
		parentPath,
		false,
		owneronly.DirectoryOwnerControlled,
		"candidate parent directory",
	)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer parent.Close()
	return l.AliasesEntry(parent, filepath.Base(path))
}

// AliasesEntry reports whether name in the already-open parent directory is
// the reserved audit entry or an existing hard link to the held audit file.
// Callers can retain parent through a subsequent descriptor-relative rename,
// eliminating path-resolution and check-then-reopen gaps.
func (l *Log) AliasesEntry(parent *os.File, name string) (bool, error) {
	if parent == nil {
		return false, errors.New("candidate parent directory is required")
	}
	if name == "" {
		return false, errors.New("candidate entry name is required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.readyLocked(); err != nil {
		return false, err
	}
	parentInfo, err := parent.Stat()
	if err != nil {
		return false, fmt.Errorf("inspect candidate parent directory: %w", err)
	}
	if name == FileName && os.SameFile(l.directoryInfo, parentInfo) {
		return true, nil
	}

	candidate, err := owneronly.OpenAtNoFollow(parent, name, os.O_RDONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("open candidate entry: %w", err)
	}
	defer candidate.Close()
	candidateInfo, err := candidate.Stat()
	if err != nil {
		return false, fmt.Errorf("inspect candidate entry: %w", err)
	}
	auditInfo, err := l.file.Stat()
	if err != nil {
		return false, fmt.Errorf("inspect audit file: %w", err)
	}
	return os.SameFile(auditInfo, candidateInfo), nil
}

// AliasesDirectory reports whether directory is the held audit/state
// directory. The caller must retain the descriptor through its mutation.
func (l *Log) AliasesDirectory(directory *os.File) (bool, error) {
	if directory == nil {
		return false, errors.New("candidate directory is required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.readyLocked(); err != nil {
		return false, err
	}
	info, err := directory.Stat()
	if err != nil {
		return false, fmt.Errorf("inspect candidate directory: %w", err)
	}
	return os.SameFile(l.directoryInfo, info), nil
}

// Append durably adds an event. It returns only after the entry has been
// written and fsynced. A write or sync failure makes this handle unusable,
// because durability is then uncertain; reopen the log to recover safely.
func (l *Log) Append(event Event) (Entry, error) {
	entry, _, err := l.AppendWithReference(event)
	return entry, err
}

// AppendWithReference durably adds an event and returns a stable reference
// that can later be read without scanning the complete log.
func (l *Log) AppendWithReference(event Event) (Entry, EntryReference, error) {
	if err := validateEvent(event); err != nil {
		return Entry{}, EntryReference{}, err
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.readyLocked(); err != nil {
		return Entry{}, EntryReference{}, err
	}
	textHash := sha256.Sum256([]byte(event.Text))
	entry := Entry{
		Seq:            l.seq + 1,
		EventID:        event.EventID,
		ExchangeID:     event.ExchangeID,
		RequestID:      event.RequestID,
		ConversationID: event.ConversationID,
		Type:           event.Type,
		Status:         event.Status,
		ErrorCode:      event.ErrorCode,
		Timestamp:      time.Now().UTC().Format(time.RFC3339Nano),
		Text:           event.Text,
		TextSHA256:     hex.EncodeToString(textHash[:]),
		Details:        cloneDetails(event.Details),
		PreviousHash:   l.head,
	}
	entryHash, err := calculateEntryHash(entry)
	if err != nil {
		return Entry{}, EntryReference{}, err
	}
	entry.EntryHash = entryHash
	line, err := json.Marshal(entry)
	if err != nil {
		return Entry{}, EntryReference{}, fmt.Errorf("encode audit entry: %w", err)
	}
	line = append(line, '\n')
	if len(line) >= maxLineSize {
		return Entry{}, EntryReference{}, fmt.Errorf("encoded audit entry is too large: %d bytes", len(line))
	}
	lineSize := int64(len(line))
	if l.size > l.maxBytes || lineSize > l.maxBytes-l.size {
		return Entry{}, EntryReference{}, fmt.Errorf(
			"%w: current %d bytes, entry %d bytes, limit %d bytes",
			ErrQuotaExceeded,
			l.size,
			lineSize,
			l.maxBytes,
		)
	}

	if err := l.io.writeFile(l.file, line); err != nil {
		l.failed = err
		return Entry{}, EntryReference{}, fmt.Errorf("append audit entry: %w", err)
	}
	if err := l.io.syncFile(l.file); err != nil {
		l.failed = err
		return Entry{}, EntryReference{}, fmt.Errorf("sync audit entry: %w", err)
	}

	reference := EntryReference{
		offset:    l.size,
		length:    lineSize,
		seq:       entry.Seq,
		entryHash: entry.EntryHash,
	}
	l.seq = entry.Seq
	l.head = entry.EntryHash
	l.size += lineSize
	return entry, reference, nil
}

// Head returns the current verified sequence and hash-chain head.
func (l *Log) Head() (uint64, string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.readyLocked(); err != nil {
		return 0, "", err
	}
	return l.seq, l.head, nil
}

// ReadAll reads and verifies the complete chain under the writer mutex.
func (l *Log) ReadAll() ([]Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.readyLocked(); err != nil {
		return nil, err
	}
	return readAndVerify(l.file)
}

// Scan verifies the complete chain and calls visit once for each entry while
// holding the writer mutex. Entries are decoded one at a time, so callers can
// inspect long logs without retaining every message in memory. The visitor
// must not call methods on l.
func (l *Log) Scan(visit func(Entry) error) error {
	if visit == nil {
		return errors.New("audit visitor is required")
	}
	return l.ScanWithReferences(func(entry Entry, _ EntryReference) error {
		return visit(entry)
	})
}

// ScanWithReferences verifies the complete chain and visits each entry with a
// stable byte reference. The visitor must not call methods on l.
func (l *Log) ScanWithReferences(visit func(Entry, EntryReference) error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.readyLocked(); err != nil {
		return err
	}
	if visit == nil {
		return errors.New("audit visitor is required")
	}
	_, err := scanAndVerify(l.file, visit)
	return err
}

// ReadReference reads and verifies one previously indexed entry under the
// writer mutex. It fails closed when the live handle is closed or poisoned.
func (l *Log) ReadReference(reference EntryReference) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.readyLocked(); err != nil {
		return Entry{}, err
	}
	if reference.offset < 0 || reference.length <= 1 || reference.length >= maxLineSize {
		return Entry{}, errors.New("invalid audit entry reference")
	}
	if reference.length > l.size || reference.offset > l.size-reference.length {
		return Entry{}, errors.New("audit entry reference is outside the verified log")
	}
	if reference.seq == 0 || !validHash(reference.entryHash) {
		return Entry{}, errors.New("invalid audit entry reference identity")
	}

	line := make([]byte, int(reference.length))
	if _, err := l.file.ReadAt(line, reference.offset); err != nil {
		return Entry{}, fmt.Errorf("read referenced audit entry: %w", err)
	}
	if line[len(line)-1] != '\n' {
		return Entry{}, errors.New("referenced audit entry is incomplete")
	}
	entry, err := decodeEntry(line[:len(line)-1])
	if err != nil {
		return Entry{}, fmt.Errorf("decode referenced audit entry: %w", err)
	}
	if entry.Seq != reference.seq || entry.EntryHash != reference.entryHash {
		return Entry{}, errors.New("referenced audit entry identity does not match")
	}
	if err := verifyEntry(entry, reference.seq, entry.PreviousHash); err != nil {
		return Entry{}, fmt.Errorf("verify referenced audit entry: %w", err)
	}
	return entry, nil
}

// Verify verifies the complete chain under the writer mutex.
func (l *Log) Verify() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.readyLocked(); err != nil {
		return err
	}
	_, err := scanAndVerify(l.file, nil)
	return err
}

func (l *Log) readyLocked() error {
	if l.file == nil {
		return ErrClosed
	}
	if l.failed != nil {
		return fmt.Errorf("%w: %v", ErrUncertainDurability, l.failed)
	}
	return nil
}

// Close closes the audit file. Every successful append was already fsynced.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	unlockErr := unlockFile(l.file)
	closeErr := l.file.Close()
	l.file = nil
	return errors.Join(unlockErr, closeErr)
}

// ReadAll reads and verifies all entries from an audit directory.
func ReadAll(dir string) ([]Entry, error) {
	directory, file, err := openExistingAudit(dir)
	if err != nil {
		return nil, err
	}
	defer closeExistingAudit(directory, file)
	return readAndVerify(file)
}

// Scan verifies the complete chain and calls visit once for each entry. Entries
// are decoded one at a time so callers do not need to retain the full log.
func Scan(dir string, visit func(Entry) error) error {
	if visit == nil {
		return errors.New("audit visitor is required")
	}
	directory, file, err := openExistingAudit(dir)
	if err != nil {
		return err
	}
	defer closeExistingAudit(directory, file)
	_, err = scanAndVerify(file, func(entry Entry, _ EntryReference) error {
		return visit(entry)
	})
	return err
}

// Verify verifies all entries in an audit directory.
func Verify(dir string) error {
	directory, file, err := openExistingAudit(dir)
	if err != nil {
		return err
	}
	defer closeExistingAudit(directory, file)
	_, err = scanAndVerify(file, nil)
	return err
}

func validateEvent(event Event) error {
	required := []struct {
		name  string
		value string
	}{
		{"event ID", event.EventID},
		{"exchange ID", event.ExchangeID},
		{"request ID", event.RequestID},
		{"conversation ID", event.ConversationID},
		{"event type", event.Type},
	}
	for _, field := range required {
		if field.value == "" {
			return fmt.Errorf("%s is required", field.name)
		}
		if !utf8.ValidString(field.value) {
			return fmt.Errorf("%s must be valid UTF-8", field.name)
		}
	}
	if !utf8.ValidString(event.Status) {
		return errors.New("status must be valid UTF-8")
	}
	if !utf8.ValidString(event.ErrorCode) {
		return errors.New("error code must be valid UTF-8")
	}
	if !utf8.ValidString(event.Text) {
		return errors.New("text must be valid UTF-8")
	}
	if len(event.Details) > 32 {
		return errors.New("audit details must not exceed 32 fields")
	}
	for key, value := range event.Details {
		if key == "" || len(key) > 64 || !utf8.ValidString(key) {
			return errors.New("audit detail key is invalid")
		}
		if len(value) > 4096 || !utf8.ValidString(value) {
			return fmt.Errorf("audit detail %q is invalid", key)
		}
	}
	return nil
}

func cloneDetails(details map[string]string) map[string]string {
	if len(details) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(details))
	for key, value := range details {
		cloned[key] = value
	}
	return cloned
}

func readAndVerify(file *os.File) ([]Entry, error) {
	entries := make([]Entry, 0)
	_, err := scanAndVerify(file, func(entry Entry, _ EntryReference) error {
		entries = append(entries, entry)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}

type scanSummary struct {
	seq  uint64
	head string
	size int64
}

func scanAndVerify(file *os.File, visit func(Entry, EntryReference) error) (scanSummary, error) {
	summary := scanSummary{head: genesisHash}
	info, err := file.Stat()
	if err != nil {
		return summary, fmt.Errorf("stat audit file: %w", err)
	}
	summary.size = info.Size()
	if info.Size() == 0 {
		return summary, nil
	}
	var finalByte [1]byte
	if _, err := file.ReadAt(finalByte[:], info.Size()-1); err != nil {
		return summary, fmt.Errorf("read audit file terminator: %w", err)
	}
	if finalByte[0] != '\n' {
		return summary, errors.New("audit log ends with an incomplete entry")
	}

	scanner := bufio.NewScanner(io.NewSectionReader(file, 0, info.Size()))
	scanner.Buffer(make([]byte, 64*1024), maxLineSize)
	// Unlike bufio.ScanLines, keep a carriage return before the newline in the
	// token. The canonical JSON check must reject CRLF, and physical byte lengths
	// must stay exact so indexed offsets cannot drift.
	scanner.Split(splitAuditLines)
	previousHash := genesisHash
	var expectedSeq uint64 = 1
	var offset int64
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			return summary, fmt.Errorf("entry %d is empty", expectedSeq)
		}
		entry, err := decodeEntry(line)
		if err != nil {
			return summary, fmt.Errorf("decode entry %d: %w", expectedSeq, err)
		}
		if err := verifyEntry(entry, expectedSeq, previousHash); err != nil {
			return summary, fmt.Errorf("verify entry %d: %w", expectedSeq, err)
		}
		lineLength := int64(len(line) + 1)
		reference := EntryReference{
			offset:    offset,
			length:    lineLength,
			seq:       entry.Seq,
			entryHash: entry.EntryHash,
		}
		if visit != nil {
			if err := visit(entry, reference); err != nil {
				return summary, fmt.Errorf("visit entry %d: %w", expectedSeq, err)
			}
		}
		offset += lineLength
		previousHash = entry.EntryHash
		summary.seq = entry.Seq
		summary.head = entry.EntryHash
		expectedSeq++
	}
	if err := scanner.Err(); err != nil {
		return summary, fmt.Errorf("read audit log: %w", err)
	}
	return summary, nil
}

func splitAuditLines(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if index := bytes.IndexByte(data, '\n'); index >= 0 {
		return index + 1, data[:index], nil
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func decodeEntry(line []byte) (Entry, error) {
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	var entry Entry
	if err := decoder.Decode(&entry); err != nil {
		return Entry{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Entry{}, errors.New("multiple JSON values in one entry")
		}
		return Entry{}, fmt.Errorf("trailing data: %w", err)
	}
	canonical, err := json.Marshal(entry)
	if err != nil {
		return Entry{}, fmt.Errorf("encode canonical entry: %w", err)
	}
	if !bytes.Equal(line, canonical) {
		return Entry{}, errors.New("entry is not canonical JSON")
	}
	return entry, nil
}

func verifyEntry(entry Entry, expectedSeq uint64, previousHash string) error {
	if entry.Seq != expectedSeq {
		return fmt.Errorf("sequence is %d, want %d", entry.Seq, expectedSeq)
	}
	if entry.PreviousHash != previousHash {
		return errors.New("previous hash does not match chain head")
	}
	if err := validateEvent(Event{
		EventID:        entry.EventID,
		ExchangeID:     entry.ExchangeID,
		RequestID:      entry.RequestID,
		ConversationID: entry.ConversationID,
		Type:           entry.Type,
		Status:         entry.Status,
		ErrorCode:      entry.ErrorCode,
		Text:           entry.Text,
		Details:        entry.Details,
	}); err != nil {
		return err
	}
	parsedTimestamp, err := time.Parse(time.RFC3339Nano, entry.Timestamp)
	if err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}
	if parsedTimestamp.Location() != time.UTC || parsedTimestamp.Format(time.RFC3339Nano) != entry.Timestamp {
		return errors.New("timestamp is not canonical UTC")
	}
	textHash := sha256.Sum256([]byte(entry.Text))
	if entry.TextSHA256 != hex.EncodeToString(textHash[:]) {
		return errors.New("text hash does not match text")
	}
	if !validHash(entry.PreviousHash) {
		return errors.New("previous hash is not lowercase SHA-256")
	}
	if !validHash(entry.EntryHash) {
		return errors.New("entry hash is not lowercase SHA-256")
	}
	expectedHash, err := calculateEntryHash(entry)
	if err != nil {
		return err
	}
	if entry.EntryHash != expectedHash {
		return errors.New("entry hash does not match content")
	}
	return nil
}

func calculateEntryHash(entry Entry) (string, error) {
	canonical, err := json.Marshal(hashableEntry{
		Seq:            entry.Seq,
		EventID:        entry.EventID,
		ExchangeID:     entry.ExchangeID,
		RequestID:      entry.RequestID,
		ConversationID: entry.ConversationID,
		Type:           entry.Type,
		Status:         entry.Status,
		ErrorCode:      entry.ErrorCode,
		Timestamp:      entry.Timestamp,
		Text:           entry.Text,
		TextSHA256:     entry.TextSHA256,
		Details:        entry.Details,
		PreviousHash:   entry.PreviousHash,
	})
	if err != nil {
		return "", fmt.Errorf("encode canonical audit entry: %w", err)
	}
	hash := sha256.Sum256(canonical)
	return hex.EncodeToString(hash[:]), nil
}

func validHash(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) != 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}
