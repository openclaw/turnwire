//go:build !darwin && !linux

package config

import "errors"

func writeConfigSecure(_ string, _ []byte, _ bool, _ DestinationGuard) error {
	return errors.New("secure config writes are unsupported on this platform")
}
