//go:build !darwin && !linux

package config

func writeConfigSecure(_ string, _ []byte, _ bool, _ DestinationGuard) error {
	panic("writeConfigSecure called on an unsupported platform")
}
