//go:build darwin || linux

package config

import (
	"os"

	"github.com/openclaw/turnwire/internal/owneronly"
)

func validateFileSecurity(file *os.File) error {
	_, err := owneronly.Validate(file, owneronly.RegularFile, "config file")
	return err
}
