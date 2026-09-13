// Package audit provides a small append-only, tamper-evident event log.
package audit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/openclaw/turnwire/internal/owneronly"
)

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
