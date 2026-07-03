//go:build darwin

package owneronly

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRejectsRealMacOSExtendedACL(t *testing.T) {
	tests := []struct {
		name string
		kind Kind
		make func(string) error
	}{
		{
			name: "file",
			kind: RegularFile,
			make: func(path string) error { return os.WriteFile(path, nil, 0o600) },
		},
		{
			name: "directory",
			kind: Directory,
			make: func(path string) error { return os.Mkdir(path, 0o700) },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "secured")
			if err := test.make(path); err != nil {
				t.Fatal(err)
			}
			if output, err := exec.Command("/bin/chmod", "+a", "everyone allow read", path).CombinedOutput(); err != nil {
				t.Skipf("cannot create a macOS ACL: %v: %s", err, output)
			}
			file, err := OpenNoFollow(path, os.O_RDONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if _, err := Validate(file, test.kind, test.name); err == nil || !strings.Contains(err.Error(), "ACL") {
				t.Fatalf("Validate() error = %v, want ACL rejection", err)
			}
			info, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			wantMode := os.FileMode(0o600)
			if test.kind == Directory {
				wantMode = 0o700
			}
			if info.Mode().Perm() != wantMode {
				t.Fatalf("ACL setup changed mode to %o, want %o", info.Mode().Perm(), wantMode)
			}
		})
	}
}

func TestValidateAncestorMacOSACLPolicy(t *testing.T) {
	tests := []struct {
		name      string
		acl       string
		wantError bool
	}{
		{name: "deny only is safe", acl: "everyone deny delete"},
		{name: "allow fails closed", acl: "everyone allow read", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ancestor")
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			if output, err := exec.Command("/bin/chmod", "+a", test.acl, path).CombinedOutput(); err != nil {
				t.Skipf("cannot create a macOS ACL: %v: %s", err, output)
			}
			t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-N", path).Run() })
			file, err := OpenDirectoryNoFollow(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			err = func() error {
				_, validateErr := ValidateAncestor(file, "test ancestor")
				return validateErr
			}()
			if (err != nil) != test.wantError {
				t.Fatalf("ValidateAncestor() error = %v, wantError %v", err, test.wantError)
			}
		})
	}
}

func TestValidateAncestorAcceptsCurrentUserHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	directory, err := OpenDirectoryNoFollow(home)
	if err != nil {
		t.Fatalf("open home directory: %v", err)
	}
	defer directory.Close()
	if _, err := ValidateAncestor(directory, "home directory"); err != nil {
		t.Fatalf("ValidateAncestor(home) = %v", err)
	}
}
