package audit

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"os"
)

// EntryReference identifies one verified entry in the append-only log without
// retaining its text in memory. References are valid for the lifetime of the
// log: successful appends never move existing bytes.
type EntryReference struct {
	offset    int64
	length    int64
	seq       uint64
	entryHash string
}

// ReadAll reads and verifies the complete chain under the writer mutex.
func (l *Log) ReadAll() ([]Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.readyLocked(); err != nil {
		return nil, err
	}
	return readAndVerify(l.file, l.cipher)
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
	_, err := scanAndVerify(l.file, l.cipher, visit)
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
	entry, err := decodeEntry(line[:len(line)-1], l.cipher)
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
	_, err := scanAndVerify(l.file, l.cipher, nil)
	return err
}

// ReadAll reads and verifies all entries from an audit directory.
func ReadAll(dir string) ([]Entry, error) {
	directory, file, err := openExistingAudit(dir)
	if err != nil {
		return nil, err
	}
	defer closeExistingAudit(directory, file)
	aead, err := loadAuditCipher(dir, false)
	if err != nil {
		return nil, fmt.Errorf("load audit encryption key: %w", err)
	}
	return readAndVerify(file, aead)
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
	aead, err := loadAuditCipher(dir, false)
	if err != nil {
		return fmt.Errorf("load audit encryption key: %w", err)
	}
	_, err = scanAndVerify(file, aead, func(entry Entry, _ EntryReference) error {
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
	aead, err := loadAuditCipher(dir, false)
	if err != nil {
		return fmt.Errorf("load audit encryption key: %w", err)
	}
	_, err = scanAndVerify(file, aead, nil)
	return err
}

func readAndVerify(file *os.File, aead cipher.AEAD) ([]Entry, error) {
	entries := make([]Entry, 0)
	_, err := scanAndVerify(file, aead, func(entry Entry, _ EntryReference) error {
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

func scanAndVerify(file *os.File, aead cipher.AEAD, visit func(Entry, EntryReference) error) (scanSummary, error) {
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
		entry, err := decodeEntry(line, aead)
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
