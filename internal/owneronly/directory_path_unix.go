//go:build darwin || linux

package owneronly

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const maxDirectorySymlinks = 40

type directoryPathOptions struct {
	syncPath      bool
	syncDirectory func(*os.File) error
}

// OpenDirectoryPath walks an absolute directory path from the filesystem root
// through held no-follow descriptors. Every ancestor is validated before the
// next lookup. Missing components are created relative to the validated parent
// when create is true. It performs no durability sync; mutation and recovery
// callers must use OpenDirectoryPathDurable.
func OpenDirectoryPath(path string, create bool, policy DirectoryPolicy, label string) (*os.File, bool, error) {
	return openDirectoryPathWithOptions(path, create, policy, label, directoryPathOptions{})
}

// OpenDirectoryPathDurable walks and validates a directory path, fsyncing each
// traversed directory and its containing parent. It recovers directory-entry
// durability after an interrupted prior create or rename.
func OpenDirectoryPathDurable(path string, create bool, policy DirectoryPolicy, label string) (*os.File, bool, error) {
	return openDirectoryPathWithOptions(path, create, policy, label, directoryPathOptions{
		syncPath: true,
		syncDirectory: func(directory *os.File) error {
			return directory.Sync()
		},
	})
}

func openDirectoryPathWithOptions(
	path string,
	create bool,
	policy DirectoryPolicy,
	label string,
	options directoryPathOptions,
) (*os.File, bool, error) {
	if !filepath.IsAbs(path) {
		return nil, false, fmt.Errorf("%s must be an absolute path", label)
	}
	if options.syncPath && options.syncDirectory == nil {
		return nil, false, fmt.Errorf("%s directory sync function is required", label)
	}
	resolved := filepath.Clean(path)
	for followed := 0; followed <= maxDirectorySymlinks; followed++ {
		directory, created, redirect, err := walkDirectoryPath(resolved, create, policy, label, options)
		if err != nil {
			return nil, false, err
		}
		if redirect == "" {
			return directory, created, nil
		}
		resolved = redirect
	}
	return nil, false, fmt.Errorf("%s has too many symbolic-link ancestors", label)
}

func walkDirectoryPath(
	path string,
	create bool,
	policy DirectoryPolicy,
	label string,
	options directoryPathOptions,
) (*os.File, bool, string, error) {
	root := string(filepath.Separator)
	current, err := OpenDirectoryNoFollow(root)
	if err != nil {
		return nil, false, "", fmt.Errorf("open %s root ancestor: %w", label, err)
	}
	closeOnError := func(openErr error) (*os.File, bool, string, error) {
		_ = current.Close()
		return nil, false, "", openErr
	}
	if _, err := ValidateAncestor(current, label+" root ancestor"); err != nil {
		return closeOnError(err)
	}

	components := splitAbsoluteDirectoryPath(path)
	if len(components) == 0 {
		if err := validateFinalDirectory(current, policy, label); err != nil {
			return closeOnError(err)
		}
		if options.syncPath {
			if err := options.syncDirectory(current); err != nil {
				return closeOnError(fmt.Errorf("sync %s component %s: %w", label, root, err))
			}
		}
		return current, false, "", nil
	}
	currentPath := root
	for index, component := range components {
		final := index == len(components)-1
		next, openErr := OpenDirectoryAtNoFollow(current, component)
		created := false
		if errors.Is(openErr, os.ErrNotExist) && create {
			mkdirErr := MkdirAt(current, component, 0o700)
			if mkdirErr == nil {
				created = true
			} else if !errors.Is(mkdirErr, os.ErrExist) {
				return closeOnError(fmt.Errorf("create %s ancestor: %w", label, mkdirErr))
			}
			next, openErr = OpenDirectoryAtNoFollow(current, component)
		}
		if openErr != nil && !errors.Is(openErr, os.ErrNotExist) {
			target, readErr := ReadTrustedSymlinkAt(current, component)
			if readErr == nil {
				if final {
					return closeOnError(fmt.Errorf("%s must not be a symbolic link", label))
				}
				if options.syncPath {
					if err := options.syncDirectory(current); err != nil {
						return closeOnError(fmt.Errorf("sync %s symbolic-link parent %s: %w", label, currentPath, err))
					}
				}
				redirect := target
				if !filepath.IsAbs(redirect) {
					redirect = filepath.Join(currentPath, redirect)
				}
				for _, remaining := range components[index+1:] {
					redirect = filepath.Join(redirect, remaining)
				}
				if err := current.Close(); err != nil {
					return nil, false, "", fmt.Errorf("close %s symbolic-link parent %s: %w", label, currentPath, err)
				}
				return nil, false, filepath.Clean(redirect), nil
			}
			if IsSymlinkLoop(openErr) || !errors.Is(readErr, ErrNotSymlink) {
				return closeOnError(fmt.Errorf("resolve %s ancestor: %w", label, readErr))
			}
		}
		if openErr != nil {
			return closeOnError(fmt.Errorf("open %s ancestor: %w", label, openErr))
		}
		if created {
			if err := next.Chmod(0o700); err != nil {
				_ = next.Close()
				return closeOnError(fmt.Errorf("secure %s ancestor: %w", label, err))
			}
		}
		nextPath := filepath.Join(currentPath, component)
		if final {
			err = validateFinalDirectory(next, policy, label)
		} else {
			_, err = ValidateAncestor(next, label+" ancestor "+nextPath)
		}
		if err != nil {
			_ = next.Close()
			return closeOnError(err)
		}
		if options.syncPath {
			if err := options.syncDirectory(next); err != nil {
				_ = next.Close()
				return closeOnError(fmt.Errorf("sync %s component %s: %w", label, nextPath, err))
			}
			if err := options.syncDirectory(current); err != nil {
				_ = next.Close()
				return closeOnError(fmt.Errorf("sync %s containing parent %s: %w", label, currentPath, err))
			}
		}
		if err := current.Close(); err != nil {
			_ = next.Close()
			return nil, false, "", fmt.Errorf("close %s ancestor: %w", label, err)
		}
		current = next
		currentPath = nextPath
		if final {
			return current, created, "", nil
		}
	}
	return closeOnError(fmt.Errorf("%s traversal did not reach a final component", label))
}

func validateFinalDirectory(directory *os.File, policy DirectoryPolicy, label string) error {
	switch policy {
	case DirectoryOwnerOnly:
		_, err := Validate(directory, Directory, label)
		return err
	case DirectoryOwnerControlled:
		_, err := ValidateOwnerControlledDirectory(directory, label)
		return err
	default:
		return errors.New("unknown directory security policy")
	}
}

func splitAbsoluteDirectoryPath(path string) []string {
	trimmed := strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator))
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, string(filepath.Separator))
}
