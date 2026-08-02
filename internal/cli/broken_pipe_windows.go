//go:build windows

package cli

import (
	"errors"
	"syscall"
)

func isPlatformBrokenPipe(err error) bool {
	var errno syscall.Errno
	// ERROR_NO_DATA is returned when the reading side of a pipe has closed.
	return errors.As(err, &errno) && (errno == syscall.ERROR_BROKEN_PIPE || errno == 232)
}
