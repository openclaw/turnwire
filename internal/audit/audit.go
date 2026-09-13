// Package audit provides a small append-only, tamper-evident event log.
package audit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/openclaw/turnwire/internal/securestore"
)

const (
	// FileName is the fixed file name used inside an audit directory.
	FileName    = "audit.jsonl"
	keyFileName = "audit.key"
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
	cipher        cipher.AEAD
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
	file, fileCreated, err := openAuditFile(directory, true, true)
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
	fileInfo, err := file.Stat()
	if err != nil {
		return closeOnError(fmt.Errorf("inspect audit file: %w", err))
	}
	aead, err := loadAuditCipher(dir, fileCreated || fileInfo.Size() == 0)
	if err != nil {
		return closeOnError(fmt.Errorf("load audit encryption key: %w", err))
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

	summary, err := scanAndVerify(file, aead, nil)
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
		cipher:        aead,
	}
	return log, nil
}

func loadAuditCipher(dir string, create bool) (cipher.AEAD, error) {
	store, err := securestore.Open(dir, create, "audit key directory")
	if err != nil {
		return nil, err
	}
	defer store.Close()
	key, err := store.Read(keyFileName)
	if errors.Is(err, os.ErrNotExist) && create {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("generate audit key: %w", err)
		}
		if err := store.Create(keyFileName, key); err != nil {
			return nil, fmt.Errorf("store audit key: %w", err)
		}
	} else if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("audit encryption key has an invalid size")
	}
	return cipher.NewGCM(block)
}

func secureStorageSupported() bool {
	return runtime.GOOS == "darwin" || runtime.GOOS == "linux"
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
	stored, err := encryptEntry(l.cipher, entry)
	if err != nil {
		return Entry{}, EntryReference{}, err
	}
	line, err := json.Marshal(stored)
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
