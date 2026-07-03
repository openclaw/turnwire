//go:build darwin || linux

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/openclaw/turnwire/internal/owneronly"
)

func openConfigFile(path string) (*os.File, error) {
	parent, name, err := openConfigParent(path, false)
	if err != nil {
		return nil, err
	}
	file, openErr := owneronly.OpenAtNoFollow(parent, name, os.O_RDONLY, 0)
	closeErr := parent.Close()
	if openErr != nil {
		return nil, openErr
	}
	if closeErr != nil {
		_ = file.Close()
		return nil, fmt.Errorf("close config directory: %w", closeErr)
	}
	return file, nil
}

func openConfigParent(path string, create bool) (*os.File, string, error) {
	parentPath := filepath.Dir(path)
	name := filepath.Base(path)
	if name == "." || name == ".." || name == string(filepath.Separator) || strings.HasSuffix(path, string(filepath.Separator)) {
		return nil, "", errors.New("config path must name a file")
	}
	absoluteParent, err := filepath.Abs(parentPath)
	if err != nil {
		return nil, "", fmt.Errorf("resolve config directory: %w", err)
	}
	var parent *os.File
	if create {
		parent, _, err = owneronly.OpenDirectoryPathDurable(
			absoluteParent,
			true,
			owneronly.DirectoryOwnerControlled,
			"config directory",
		)
	} else {
		parent, _, err = owneronly.OpenDirectoryPath(
			absoluteParent,
			false,
			owneronly.DirectoryOwnerControlled,
			"config directory",
		)
	}
	if err != nil {
		return nil, "", err
	}
	return parent, name, nil
}
