// Source-export root types. Robert F. Tilley Jr.; G-14, Inc.
package corpus

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSourceHashRefusesRegularFileRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "regular.go")
	if err := os.WriteFile(root, []byte("package main\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		path string
		hash func(string) (string, error)
	}{
		{"public", root, SourceHash},
		{"private_zero_budget", root, func(p string) (string, error) { return sourceHash(p, 0) }},
		{"public_trailing_separator", root + string(os.PathSeparator), SourceHash},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.hash(tc.path)
			if got != "" || err == nil || !strings.Contains(err.Error(), "source root is not a directory") {
				t.Fatalf("regular file root must be refused without a digest: got=%q err=%v", got, err)
			}
		})
	}
}

func TestSourceHashDirectoryRootControls(t *testing.T) {
	root := t.TempDir()
	contents := []byte("one")
	if err := os.WriteFile(filepath.Join(root, "entry.txt"), contents, 0600); err != nil {
		t.Fatal(err)
	}
	// Independently construct the canonical one-entry manifest: no root '.' entry.
	manifest := fmt.Sprintf("[{\"path\":\"entry.txt\",\"sha256\":\"%x\",\"size_bytes\":3}]", sha256.Sum256(contents))
	want := fmt.Sprintf("%x", sha256.Sum256([]byte(manifest)))
	for _, tc := range []struct {
		name string
		path string
		hash func(string) (string, error)
	}{
		{"public", root, SourceHash},
		{"public_trailing_separator", root + string(os.PathSeparator), SourceHash},
		{"private_exact_budget", root, func(p string) (string, error) { return sourceHash(p, 1) }},
		{"private_exact_budget_trailing_separator", root + string(os.PathSeparator), func(p string) (string, error) { return sourceHash(p, 1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.hash(tc.path)
			if err != nil || got != want {
				t.Fatalf("valid directory must preserve manifest digest: got=%q err=%v want=%q", got, err, want)
			}
		})
	}
}

func TestSourceHashRootRefusalPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind string
		want string
	}{
		{"git_file", "file", "source must be a clean export"},
		{"git_directory", "directory", "source must be a clean export"},
		{"git_symlink_to_file", "symlink_file", "source symlink"},
		{"git_symlink_to_directory", "symlink_directory", "source symlink"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			root := filepath.Join(base, ".git")
			switch tc.kind {
			case "file":
				if err := os.WriteFile(root, []byte("metadata"), 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(root, 0700); err != nil {
					t.Fatal(err)
				}
			default:
				target := filepath.Join(base, "target")
				if tc.kind == "symlink_directory" {
					if err := os.Mkdir(target, 0700); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(target, []byte("target"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, root); err != nil {
					t.Skipf("host cannot create symlink: %v", err)
				}
			}
			for _, call := range []struct {
				name string
				hash func(string) (string, error)
			}{
				{"public", SourceHash},
				{"private_zero_budget", func(p string) (string, error) { return sourceHash(p, 0) }},
			} {
				t.Run(call.name, func(t *testing.T) {
					got, err := call.hash(root)
					if got != "" || err == nil || !strings.Contains(err.Error(), tc.want) {
						t.Fatalf("root guard precedence must remain: got=%q err=%v want=%q", got, err, tc.want)
					}
				})
			}
		})
	}
}
