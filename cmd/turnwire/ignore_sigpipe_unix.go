//go:build unix

package main

import (
	"os/signal"
	"syscall"
)

// ignoreBrokenPipeSignal prevents SIGPIPE from terminating the process on a
// closed stdout/stderr pipe so write errors can surface as EPIPE and the CLI
// can treat broken pipes as clean success.
func ignoreBrokenPipeSignal() {
	signal.Ignore(syscall.SIGPIPE)
}
