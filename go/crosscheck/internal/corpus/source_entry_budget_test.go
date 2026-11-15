// Source-export descendant entry limits. Robert F. Tilley Jr.; G-14, Inc.
package corpus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSourceHashDescendantEntryBudget(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "first"), []byte("one"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "second"), []byte("two"), 0600); err != nil {
		t.Fatal(err)
	}
	// The real walker sees one directory and two regular files below root.
	// A smaller private budget exercises its exact boundary without a huge fixture.
	want, err := SourceHash(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		limit  int
		accept bool
	}{
		{"one_over_budget", 2, false},
		{"exact_budget", 3, true},
		{"one_under_budget", 4, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sourceHash(root, tc.limit)
			if tc.accept {
				if err != nil || got != want {
					t.Fatalf("three descendants within limit %d: digest=%q err=%v; want %q", tc.limit, got, err, want)
				}
			} else if err == nil || !strings.Contains(err.Error(), "entry budget exceeded") || got != "" {
				t.Fatalf("three descendants exceed limit %d: digest=%q err=%v", tc.limit, got, err)
			}
		})
	}
}

func TestSourceHashRootChecksOutsideDescendantBudget(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if _, err := sourceHash(t.TempDir(), 0); err == nil || !strings.Contains(err.Error(), "source tree is empty") {
			t.Fatalf("empty root must retain empty-source refusal: %v", err)
		}
	})
	t.Run("git", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), ".git")
		if err := os.Mkdir(root, 0700); err != nil {
			t.Fatal(err)
		}
		if _, err := sourceHash(root, 0); err == nil || !strings.Contains(err.Error(), "clean export") {
			t.Fatalf("metadata root must retain metadata refusal: %v", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		base := t.TempDir()
		target := filepath.Join(base, "target")
		if err := os.Mkdir(target, 0700); err != nil {
			t.Fatal(err)
		}
		root := filepath.Join(base, "alias")
		if err := os.Symlink(target, root); err != nil {
			t.Skipf("host cannot create test symlink: %v", err)
		}
		if _, err := sourceHash(root, 0); err == nil || !strings.Contains(err.Error(), "source symlink") {
			t.Fatalf("symlink root must retain symlink refusal: %v", err)
		}
	})
}
