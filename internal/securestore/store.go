// Package securestore provides small immutable files in an owner-only directory.
package securestore

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/openclaw/turnwire/internal/owneronly"
)

const maxFileBytes = 2 << 20

// Store holds a validated directory descriptor for no-follow file operations.
type Store struct {
	directory *os.File
}

// Open opens or creates an owner-only directory.
func Open(path string, create bool, label string) (*Store, error) {
	directory, _, err := owneronly.OpenDirectoryPathDurable(
		path,
		create,
		owneronly.DirectoryOwnerOnly,
		label,
	)
	if err != nil {
		return nil, err
	}
	return &Store{directory: directory}, nil
}

// Close releases the held directory descriptor.
func (s *Store) Close() error {
	if s == nil || s.directory == nil {
		return nil
	}
	err := s.directory.Close()
	s.directory = nil
	return err
}

// AliasesDirectory reports whether candidate is this store's held directory.
func (s *Store) AliasesDirectory(candidate *os.File) (bool, error) {
	if s == nil || s.directory == nil || candidate == nil {
		return false, errors.New("secure store directory is not open")
	}
	storeInfo, err := s.directory.Stat()
	if err != nil {
		return false, fmt.Errorf("inspect secure store directory: %w", err)
	}
	candidateInfo, err := candidate.Stat()
	if err != nil {
		return false, fmt.Errorf("inspect candidate directory: %w", err)
	}
	return os.SameFile(storeInfo, candidateInfo), nil
}

// Create writes and syncs a new immutable owner-only file.
func (s *Store) Create(name string, data []byte) error {
	if err := validateName(name); err != nil {
		return err
	}
	if len(data) == 0 || len(data) > maxFileBytes {
		return errors.New("secure store value has an invalid size")
	}
	file, err := owneronly.OpenAtNoFollow(
		s.directory,
		name,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		0o600,
	)
	if err != nil {
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("secure stored value: %w", err)
	}
	if _, err := owneronly.Validate(file, owneronly.RegularFile, "secure stored value"); err != nil {
		_ = file.Close()
		return err
	}
	if err := writeAll(file, data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write secure stored value: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync secure stored value: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close secure stored value: %w", err)
	}
	if err := s.directory.Sync(); err != nil {
		return fmt.Errorf("sync secure store directory: %w", err)
	}
	return nil
}

// Read reads one validated owner-only file with a fixed memory bound.
func (s *Store) Read(name string) ([]byte, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}
	file, err := owneronly.OpenAtNoFollow(s.directory, name, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if _, err := owneronly.Validate(file, owneronly.RegularFile, "secure stored value"); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read secure stored value: %w", err)
	}
	if len(data) == 0 || len(data) > maxFileBytes {
		return nil, errors.New("secure stored value has an invalid size")
	}
	return data, nil
}

func validateName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") {
		return errors.New("secure store file name is invalid")
	}
	return nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
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
