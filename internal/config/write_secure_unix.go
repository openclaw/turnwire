//go:build darwin || linux

package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/openclaw/turnwire/internal/owneronly"
)

func writeConfigSecure(path string, contents []byte, force bool, guard DestinationGuard) error {
	parent, name, err := openConfigParent(path, true)
	if err != nil {
		return err
	}
	defer parent.Close()
	if guard != nil {
		if err := guard(parent, name); err != nil {
			return err
		}
	}

	exists, err := configEntryExists(parent, name)
	if err != nil {
		return err
	}
	if exists && !force {
		return fmt.Errorf("create config file: %w", os.ErrExist)
	}

	if !force {
		return createConfigAt(parent, name, contents)
	}
	return replaceConfigAt(parent, name, contents)
}

func configEntryExists(parent *os.File, name string) (bool, error) {
	file, err := owneronly.OpenAtNoFollow(parent, name, os.O_RDONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect config file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return false, fmt.Errorf("inspect config file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return false, errors.New("config file must be a regular file, not a symbolic link")
	}
	return true, nil
}

func createConfigAt(parent *os.File, name string, contents []byte) error {
	file, err := owneronly.OpenAtNoFollow(
		parent,
		name,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		0o600,
	)
	if err != nil {
		return fmt.Errorf("create config file: %w", err)
	}
	cleanup := true
	defer func() {
		_ = file.Close()
		if cleanup {
			_ = owneronly.UnlinkAt(parent, name)
		}
	}()
	if err := prepareAndWriteConfig(file, contents); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close config file: %w", err)
	}
	if err := parent.Sync(); err != nil {
		return fmt.Errorf("sync config directory: %w", err)
	}
	cleanup = false
	return nil
}

func replaceConfigAt(parent *os.File, name string, contents []byte) error {
	temporary, temporaryName, err := createTemporaryConfig(parent)
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		_ = temporary.Close()
		if cleanup {
			_ = owneronly.UnlinkAt(parent, temporaryName)
		}
	}()
	if err := prepareAndWriteConfig(temporary, contents); err != nil {
		return err
	}
	temporaryInfo, err := temporary.Stat()
	if err != nil {
		return fmt.Errorf("inspect temporary config file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary config file: %w", err)
	}
	if err := owneronly.RenameAt(parent, temporaryName, name); err != nil {
		return fmt.Errorf("replace config file: %w", err)
	}
	cleanup = false

	written, err := owneronly.OpenAtNoFollow(parent, name, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("open replaced config file: %w", err)
	}
	writtenInfo, err := owneronly.Validate(written, owneronly.RegularFile, "config file")
	if err != nil {
		_ = written.Close()
		return err
	}
	if !os.SameFile(temporaryInfo, writtenInfo) {
		_ = written.Close()
		return errors.New("config file changed during replacement")
	}
	if err := written.Close(); err != nil {
		return fmt.Errorf("close replaced config file: %w", err)
	}
	if err := parent.Sync(); err != nil {
		return fmt.Errorf("sync config directory: %w", err)
	}
	return nil
}

func createTemporaryConfig(parent *os.File) (*os.File, string, error) {
	for attempt := 0; attempt < 100; attempt++ {
		var random [12]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", fmt.Errorf("generate temporary config name: %w", err)
		}
		name := ".turnwire-config-" + hex.EncodeToString(random[:]) + ".tmp"
		file, err := owneronly.OpenAtNoFollow(
			parent,
			name,
			os.O_CREATE|os.O_EXCL|os.O_WRONLY,
			0o600,
		)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("create temporary config file: %w", err)
		}
		return file, name, nil
	}
	return nil, "", errors.New("create temporary config file: too many name collisions")
}

func prepareAndWriteConfig(file *os.File, contents []byte) error {
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("secure config file: %w", err)
	}
	if err := validateFileSecurity(file); err != nil {
		return err
	}
	for len(contents) != 0 {
		written, err := file.Write(contents)
		if err != nil {
			return fmt.Errorf("write config file: %w", err)
		}
		if written == 0 {
			return fmt.Errorf("write config file: %w", io.ErrShortWrite)
		}
		contents = contents[written:]
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync config file: %w", err)
	}
	return nil
}
