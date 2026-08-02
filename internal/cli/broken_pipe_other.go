//go:build !unix && !windows

package cli

func isPlatformBrokenPipe(error) bool {
	return false
}
