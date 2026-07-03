//go:build linux

package owneronly

import (
	"bytes"
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

func hasExtendedACL(file *os.File) (bool, error) {
	for _, name := range [...]string{
		"system.posix_acl_access",
		"system.posix_acl_default",
		"system.nfs4_acl",
		"system.richacl",
		"system.cifs_acl",
		"system.smb3_acl",
	} {
		_, err := unix.Fgetxattr(int(file.Fd()), name, nil)
		switch {
		case err == nil:
			// A mode-only ACL is normally elided by the kernel. Reject any
			// persisted ACL representation rather than trying to reproduce the
			// kernel's effective-access calculation here.
			return true, nil
		case errors.Is(err, unix.ENODATA):
			continue
		case errors.Is(err, unix.EOPNOTSUPP):
			// This filesystem cannot carry POSIX ACLs through Linux's ACL
			// interface, so there is no extended grant to inspect.
			continue
		default:
			return false, err
		}
	}
	names, err := listExtendedAttributes(file)
	if err != nil {
		return false, err
	}
	for _, rawName := range bytes.Split(names, []byte{0}) {
		name := strings.ToLower(string(rawName))
		if name == "" || !strings.Contains(name, "acl") {
			continue
		}
		if strings.HasPrefix(name, "system.") || strings.HasPrefix(name, "security.") || strings.HasPrefix(name, "trusted.") {
			return true, nil
		}
	}
	return false, nil
}

func hasUnsafeAncestorACL(file *os.File) (bool, error) {
	// Linux POSIX/default ACL entries can alter effective mutation rights or
	// inheritance. Filesystem-specific ACL xattrs are not portable enough to
	// prove safe, so every detected ACL fails closed for an ancestor.
	return hasExtendedACL(file)
}

func listExtendedAttributes(file *os.File) ([]byte, error) {
	for attempt := 0; attempt < 3; attempt++ {
		size, err := unix.Flistxattr(int(file.Fd()), nil)
		if errors.Is(err, unix.EOPNOTSUPP) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if size == 0 {
			return nil, nil
		}
		buffer := make([]byte, size)
		read, err := unix.Flistxattr(int(file.Fd()), buffer)
		if errors.Is(err, unix.ERANGE) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return buffer[:read], nil
	}
	return nil, unix.ERANGE
}
