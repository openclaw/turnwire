//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !windows

package audit

import (
	"errors"
	"os"
)

func lockFile(_ *os.File) error {
	return errors.New("audit file locking is unsupported on this platform")
}

func unlockFile(_ *os.File) error {
	return nil
}
