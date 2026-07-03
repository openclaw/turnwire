//go:build darwin || linux

package owneronly

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// OpenNoFollow opens a path without following its final symbolic link.
func OpenNoFollow(path string, flag int, perm os.FileMode) (*os.File, error) {
	fd, err := unix.Open(path, flag|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, uint32(perm.Perm()))
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

// OpenAtNoFollow opens one name relative to an already-open directory. Names
// containing separators are rejected so every lookup remains descriptor-bound.
func OpenAtNoFollow(directory *os.File, name string, flag int, perm os.FileMode) (*os.File, error) {
	if directory == nil {
		return nil, unix.EBADF
	}
	if err := validateEntryName(name); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(
		int(directory.Fd()),
		name,
		flag|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK,
		uint32(perm.Perm()),
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

// OpenDirectoryNoFollow opens the final directory itself without following a
// symlink. Subsequent file access should use OpenAtNoFollow with this handle.
func OpenDirectoryNoFollow(path string) (*os.File, error) {
	return OpenNoFollow(path, unix.O_RDONLY|unix.O_DIRECTORY, 0)
}

// OpenDirectoryAtNoFollow opens one directory entry relative to a held parent.
func OpenDirectoryAtNoFollow(parent *os.File, name string) (*os.File, error) {
	return OpenAtNoFollow(parent, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
}

// MkdirAt creates one directory entry relative to a held parent.
func MkdirAt(parent *os.File, name string, perm os.FileMode) error {
	if parent == nil {
		return unix.EBADF
	}
	if err := validateEntryName(name); err != nil {
		return err
	}
	return unix.Mkdirat(int(parent.Fd()), name, uint32(perm.Perm()))
}

// ReadTrustedSymlinkAt resolves a symlink entry only when root or the current
// user owns the link. The containing directory must already have passed
// ValidateAncestor, which prevents an unprivileged replacement race.
func ReadTrustedSymlinkAt(parent *os.File, name string) (string, error) {
	if parent == nil {
		return "", unix.EBADF
	}
	if err := validateEntryName(name); err != nil {
		return "", err
	}
	var before unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return "", err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFLNK {
		return "", ErrNotSymlink
	}
	owner := int(before.Uid)
	if owner != 0 && owner != os.Geteuid() {
		return "", errors.New("symbolic-link ancestor must be owned by root or the current user")
	}

	buffer := make([]byte, 256)
	var target string
	for {
		read, err := unix.Readlinkat(int(parent.Fd()), name, buffer)
		if err != nil {
			return "", err
		}
		if read < len(buffer) {
			target = string(buffer[:read])
			break
		}
		if len(buffer) >= 1<<20 {
			return "", errors.New("symbolic-link target is too long")
		}
		buffer = make([]byte, len(buffer)*2)
	}
	if target == "" {
		return "", errors.New("symbolic-link target is empty")
	}
	var after unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), name, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return "", err
	}
	if before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode || before.Uid != after.Uid {
		return "", fmt.Errorf("symbolic-link ancestor changed while being read")
	}
	return target, nil
}

// IsSymlinkLoop reports the platform error returned when O_NOFOLLOW reaches a
// symbolic link.
func IsSymlinkLoop(err error) bool {
	return errors.Is(err, unix.ELOOP)
}

// RenameAt atomically renames one entry within a held directory, replacing a
// destination entry according to the host rename(2) semantics.
func RenameAt(directory *os.File, oldName, newName string) error {
	if directory == nil {
		return unix.EBADF
	}
	if err := validateEntryName(oldName); err != nil {
		return err
	}
	if err := validateEntryName(newName); err != nil {
		return err
	}
	return unix.Renameat(int(directory.Fd()), oldName, int(directory.Fd()), newName)
}

// UnlinkAt removes one non-directory entry within a held directory.
func UnlinkAt(directory *os.File, name string) error {
	if directory == nil {
		return unix.EBADF
	}
	if err := validateEntryName(name); err != nil {
		return err
	}
	return unix.Unlinkat(int(directory.Fd()), name, 0)
}

func validateEntryName(name string) error {
	if name == "" {
		return unix.ENOENT
	}
	if name == "." || name == ".." {
		return unix.EINVAL
	}
	for _, character := range name {
		if character == '/' {
			return unix.EINVAL
		}
	}
	return nil
}
