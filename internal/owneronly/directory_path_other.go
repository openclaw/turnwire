//go:build !darwin && !linux

package owneronly

import "os"

func OpenDirectoryPath(_ string, _ bool, _ DirectoryPolicy, _ string) (*os.File, bool, error) {
	return nil, false, ErrUnsupported
}

func OpenDirectoryPathDurable(_ string, _ bool, _ DirectoryPolicy, _ string) (*os.File, bool, error) {
	return nil, false, ErrUnsupported
}
