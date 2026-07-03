//go:build darwin || linux

package owneronly

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenDirectoryPathDurableSyncsExistingChildBeforeParent(t *testing.T) {
	target, parent := existingSyncFixture(t)
	targetInfo := statPath(t, target)
	parentInfo := statPath(t, parent)
	var sequence []string
	directory, created, err := openDirectoryPathWithOptions(
		target,
		false,
		DirectoryOwnerOnly,
		"test directory",
		directoryPathOptions{
			syncPath: true,
			syncDirectory: func(file *os.File) error {
				info, err := file.Stat()
				if err != nil {
					return err
				}
				sequence = appendFixtureSync(sequence, info, targetInfo, parentInfo)
				return nil
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := directory.Close(); err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("existing target reported as created")
	}
	if got := strings.Join(sequence, ","); got != "parent,target,parent" {
		t.Fatalf("fixture sync sequence = %q, want child-before-parent edge ordering", got)
	}
}

func TestOpenDirectoryPathNonDurableDoesNotSync(t *testing.T) {
	target, _ := existingSyncFixture(t)
	syncCalls := 0
	directory, created, err := openDirectoryPathWithOptions(
		target,
		false,
		DirectoryOwnerOnly,
		"read directory",
		directoryPathOptions{
			syncPath: false,
			syncDirectory: func(*os.File) error {
				syncCalls++
				return errors.New("non-durable traversal unexpectedly synced")
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := directory.Close(); err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("existing target reported as created")
	}
	if syncCalls != 0 {
		t.Fatalf("non-durable traversal sync calls = %d, want 0", syncCalls)
	}
}

func TestOpenDirectoryPathPropagatesRecoverySyncFailuresAndRetries(t *testing.T) {
	target, parent := existingSyncFixture(t)
	targetInfo := statPath(t, target)
	parentInfo := statPath(t, parent)
	injected := errors.New("injected directory sync failure")
	tests := []struct {
		name      string
		wantLabel string
	}{
		{name: "component", wantLabel: "component"},
		{name: "containing parent", wantLabel: "containing parent"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parentSyncs := 0
			directory, _, err := openDirectoryPathWithOptions(
				target,
				false,
				DirectoryOwnerOnly,
				"recovery directory",
				directoryPathOptions{
					syncPath: true,
					syncDirectory: func(file *os.File) error {
						info, err := file.Stat()
						if err != nil {
							return err
						}
						if test.name == "component" && os.SameFile(info, targetInfo) {
							return injected
						}
						if test.name == "containing parent" && os.SameFile(info, parentInfo) {
							parentSyncs++
							if parentSyncs == 2 {
								return injected
							}
						}
						return nil
					},
				},
			)
			if directory != nil {
				_ = directory.Close()
				t.Fatal("sync failure returned an open directory")
			}
			wantPath := target
			if test.name == "containing parent" {
				wantPath = parent
			}
			if !errors.Is(err, injected) || !strings.Contains(err.Error(), test.wantLabel) || !strings.Contains(err.Error(), wantPath) {
				t.Fatalf("OpenDirectoryPath error = %v, want injected %q failure", err, test.wantLabel)
			}

			var retrySequence []string
			retried, created, err := openDirectoryPathWithOptions(
				target,
				false,
				DirectoryOwnerOnly,
				"recovery directory",
				directoryPathOptions{
					syncPath: true,
					syncDirectory: func(file *os.File) error {
						info, err := file.Stat()
						if err != nil {
							return err
						}
						retrySequence = appendFixtureSync(retrySequence, info, targetInfo, parentInfo)
						return file.Sync()
					},
				},
			)
			if err != nil {
				t.Fatalf("retry after sync failure: %v", err)
			}
			if created {
				_ = retried.Close()
				t.Fatal("retry reported existing target as created")
			}
			if err := retried.Close(); err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(retrySequence, ","); got != "parent,target,parent" {
				t.Fatalf("retry sync sequence = %q, want complete child-before-parent recovery", got)
			}
		})
	}
}

func appendFixtureSync(sequence []string, info, targetInfo, parentInfo os.FileInfo) []string {
	if os.SameFile(info, targetInfo) {
		sequence = append(sequence, "target")
	}
	if os.SameFile(info, parentInfo) {
		sequence = append(sequence, "parent")
	}
	return sequence
}

func existingSyncFixture(t *testing.T) (target string, parent string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	parent = filepath.Join(root, "parent")
	target = filepath.Join(parent, "target")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	return target, parent
}

func statPath(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}
