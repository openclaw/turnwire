//go:build unix

package cli

import (
	"syscall"
	"testing"
)

func TestIsPlatformBrokenPipeAcceptsEPIPE(t *testing.T) {
	t.Parallel()
	if !isPlatformBrokenPipe(syscall.EPIPE) {
		t.Fatal("EPIPE was not classified as a broken pipe")
	}
}

func TestIsPlatformBrokenPipeRejectsWindowsErrnoOnUnix(t *testing.T) {
	t.Parallel()
	if isPlatformBrokenPipe(syscall.Errno(109)) {
		t.Fatal("Unix errno 109 was classified as a broken pipe")
	}
}
