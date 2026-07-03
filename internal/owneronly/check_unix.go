//go:build darwin || linux

// Package owneronly validates security-sensitive files through their open
// descriptors, so path replacement cannot invalidate the result.
package owneronly

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// Kind is the descriptor type expected by Validate.
type Kind uint8

const (
	RegularFile Kind = iota
	Directory
)

// Validate requires an owner-only regular file or directory owned by the
// effective user, with no extended access or inherited ACL.
func Validate(file *os.File, kind Kind, label string) (os.FileInfo, error) {
	return validate(file, kind, label, 0o077)
}

// ValidateOwnerControlledDirectory permits group/other read and traversal but
// rejects every non-owner write path and every extended ACL. It is intended
// for a configuration parent that may conventionally be 0755.
func ValidateOwnerControlledDirectory(file *os.File, label string) (os.FileInfo, error) {
	return validate(file, Directory, label, 0o022)
}

// ValidateAncestor requires an ancestor that an unprivileged sibling cannot
// use to rename or replace the next path component. Root and the effective
// user are trusted owners. Group/other-writable ancestors are accepted only
// with sticky-directory semantics, and ACL allow entries fail closed.
func ValidateAncestor(file *os.File, label string) (os.FileInfo, error) {
	if file == nil {
		return nil, errors.New("file descriptor is required")
	}
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect open %s: %w", label, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s must be a real directory", label)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("cannot verify %s ownership", label)
	}
	owner := int(stat.Uid)
	if owner != 0 && owner != os.Geteuid() {
		return nil, fmt.Errorf("%s must be owned by root or the current user", label)
	}
	if info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
		return nil, fmt.Errorf("%s is writable by non-owner users without sticky-directory protection", label)
	}
	unsafeACL, err := hasUnsafeAncestorACL(file)
	if err != nil {
		return nil, fmt.Errorf("inspect %s ACL: %w", label, err)
	}
	if unsafeACL {
		return nil, fmt.Errorf("%s has an ACL that may grant non-owner access", label)
	}
	return info, nil
}

func validate(file *os.File, kind Kind, label string, forbidden os.FileMode) (os.FileInfo, error) {
	if file == nil {
		return nil, errors.New("file descriptor is required")
	}
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect open %s: %w", label, err)
	}
	switch kind {
	case RegularFile:
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%s must be a regular file", label)
		}
	case Directory:
		if !info.IsDir() {
			return nil, fmt.Errorf("%s must be a real directory", label)
		}
	default:
		return nil, errors.New("unknown owner-only object kind")
	}
	if info.Mode().Perm()&forbidden != 0 {
		return nil, fmt.Errorf("%s permissions are too broad: group or other users have readable, writable, or executable access", label)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("cannot verify %s ownership", label)
	}
	if int(stat.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("%s must be owned by the current user", label)
	}
	hasACL, err := hasExtendedACL(file)
	if err != nil {
		return nil, fmt.Errorf("inspect %s ACL: %w", label, err)
	}
	if hasACL {
		return nil, fmt.Errorf("%s must not have an extended or inherited ACL", label)
	}
	return info, nil
}
