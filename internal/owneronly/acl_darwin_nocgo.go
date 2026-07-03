//go:build darwin && !cgo

package owneronly

import (
	"errors"
	"os"
)

func hasExtendedACL(_ *os.File) (bool, error) {
	return false, errors.New("macOS ACL validation requires cgo")
}

func hasUnsafeAncestorACL(_ *os.File) (bool, error) {
	return false, errors.New("macOS ACL validation requires cgo")
}
