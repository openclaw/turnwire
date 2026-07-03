//go:build linux

package owneronly

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestValidateRejectsLinuxPOSIXACLs(t *testing.T) {
	t.Run("access ACL on file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "secured")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		setLinuxACL(t, path, "system.posix_acl_access", linuxAccessACL())
		// chmod updates the POSIX mask to zero while retaining the named ACL,
		// reproducing an extended ACL hidden behind an apparent 0600 mode.
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
		assertRejectsACL(t, path, RegularFile, 0o600)
	})

	t.Run("inherited ACL on directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "secured")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		setLinuxACL(t, path, "system.posix_acl_default", linuxDefaultACL())
		assertRejectsACL(t, path, Directory, 0o700)
	})
}

func assertRejectsACL(t *testing.T, path string, kind Kind, wantMode os.FileMode) {
	t.Helper()
	file, err := OpenNoFollow(path, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != wantMode {
		t.Fatalf("mode = %o, want %o", info.Mode().Perm(), wantMode)
	}
	if _, err := Validate(file, kind, "secured object"); err == nil || !strings.Contains(err.Error(), "ACL") {
		t.Fatalf("Validate() error = %v, want ACL rejection", err)
	}
	if kind == Directory {
		if _, err := ValidateAncestor(file, "secured ancestor"); err == nil || !strings.Contains(err.Error(), "ACL") {
			t.Fatalf("ValidateAncestor() error = %v, want ACL rejection", err)
		}
	}
}

func setLinuxACL(t *testing.T, path, name string, value []byte) {
	t.Helper()
	err := unix.Setxattr(path, name, value, 0)
	if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EPERM) {
		t.Skipf("filesystem does not permit POSIX ACL test setup: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func linuxAccessACL() []byte {
	return encodeLinuxACL([]linuxACLEntry{
		{tag: 0x01, perm: 0o6, id: ^uint32(0)},
		{tag: 0x02, perm: 0o4, id: 1},
		{tag: 0x04, perm: 0o0, id: ^uint32(0)},
		{tag: 0x10, perm: 0o4, id: ^uint32(0)},
		{tag: 0x20, perm: 0o0, id: ^uint32(0)},
	})
}

func linuxDefaultACL() []byte {
	return encodeLinuxACL([]linuxACLEntry{
		{tag: 0x01, perm: 0o7, id: ^uint32(0)},
		{tag: 0x02, perm: 0o4, id: 1},
		{tag: 0x04, perm: 0o0, id: ^uint32(0)},
		{tag: 0x10, perm: 0o4, id: ^uint32(0)},
		{tag: 0x20, perm: 0o0, id: ^uint32(0)},
	})
}

type linuxACLEntry struct {
	tag  uint16
	perm uint16
	id   uint32
}

func encodeLinuxACL(entries []linuxACLEntry) []byte {
	encoded := make([]byte, 4+len(entries)*8)
	binary.LittleEndian.PutUint32(encoded, 0x0002)
	for index, entry := range entries {
		offset := 4 + index*8
		binary.LittleEndian.PutUint16(encoded[offset:], entry.tag)
		binary.LittleEndian.PutUint16(encoded[offset+2:], entry.perm)
		binary.LittleEndian.PutUint32(encoded[offset+4:], entry.id)
	}
	return encoded
}
