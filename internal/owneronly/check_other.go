//go:build !darwin && !linux

package owneronly

import (
	"errors"
	"os"
)

// Kind is the descriptor type expected by Validate.
type Kind uint8

const (
	RegularFile Kind = iota
	Directory
)

var ErrUnsupported = errors.New("owner-only filesystem validation is unsupported on this platform")

func Validate(_ *os.File, _ Kind, _ string) (os.FileInfo, error) {
	return nil, ErrUnsupported
}

func ValidateOwnerControlledDirectory(_ *os.File, _ string) (os.FileInfo, error) {
	return nil, ErrUnsupported
}

func ValidateAncestor(_ *os.File, _ string) (os.FileInfo, error) {
	return nil, ErrUnsupported
}

func OpenNoFollow(path string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flag, perm)
}

func OpenAtNoFollow(_ *os.File, _ string, _ int, _ os.FileMode) (*os.File, error) {
	return nil, ErrUnsupported
}

func OpenDirectoryNoFollow(path string) (*os.File, error) {
	return os.Open(path)
}

func OpenDirectoryAtNoFollow(_ *os.File, _ string) (*os.File, error) {
	return nil, ErrUnsupported
}

func MkdirAt(_ *os.File, _ string, _ os.FileMode) error {
	return ErrUnsupported
}

func ReadTrustedSymlinkAt(_ *os.File, _ string) (string, error) {
	return "", ErrUnsupported
}

func IsSymlinkLoop(_ error) bool {
	return false
}

func RenameAt(_ *os.File, _, _ string) error {
	return ErrUnsupported
}

func UnlinkAt(_ *os.File, _ string) error {
	return ErrUnsupported
}
