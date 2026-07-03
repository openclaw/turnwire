//go:build !darwin && !linux

package config

import "os"

func validateFileSecurity(_ *os.File) error {
	return nil
}
