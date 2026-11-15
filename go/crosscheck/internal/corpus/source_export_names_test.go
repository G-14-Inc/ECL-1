// Exact source-export names and refusal controls. Robert F. Tilley Jr.; G-14, Inc.
package corpus

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

func TestSourceExportExactNames(t *testing.T) {
	for _, name := range []string{"notes 1.txt", "café.txt", "cafe\u0301.txt", "\ue000.txt", "\U00010000.txt", "a\u2028b\u2029.txt", "\ufffd.txt", "\ufeffname.txt", "CON.txt", "notes.", "notes ", "name:stream.txt"} {
		t.Run(name, func(t *testing.T) {
			if runtime.GOOS == "windows" && (name == "CON.txt" || name == "notes." || name == "notes " || name == "name:stream.txt") {
				t.Skip("host filename restriction")
			}
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, name), []byte("x"), 0600); err != nil {
				t.Fatal(err)
			}
			entries, err := os.ReadDir(root)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Name() != name {
				t.Skip("host normalizes the requested filename")
			}
			got, err := SourceHash(root)
			if err != nil {
				t.Fatal(err)
			}
			fileHash := sha256.Sum256([]byte("x"))
			quoted, _ := json.Marshal(name)
			// encoding/json escapes U+2028/U+2029; the source profile writes their UTF-8 bytes.
			pathJSON := string(quoted)
			for i := 0; i+6 <= len(pathJSON); i++ {
				if pathJSON[i:i+6] == `\u2028` {
					pathJSON = pathJSON[:i] + "\u2028" + pathJSON[i+6:]
				}
				if i+6 <= len(pathJSON) && pathJSON[i:i+6] == `\u2029` {
					pathJSON = pathJSON[:i] + "\u2029" + pathJSON[i+6:]
				}
			}
			manifest := `[{"path":` + pathJSON + `,"sha256":"` + hex.EncodeToString(fileHash[:]) + `","size_bytes":1}]`
			want := sha256.Sum256([]byte(manifest))
			if got != hex.EncodeToString(want[:]) {
				t.Fatalf("got %s; manifest %s", got, manifest)
			}
		})
	}
}
func TestSourceExportRejectsGitFileAndDirectory(t *testing.T) {
	for _, directory := range []bool{false, true} {
		root := t.TempDir()
		os.WriteFile(filepath.Join(root, "control"), []byte("x"), 0600)
		if directory {
			os.Mkdir(filepath.Join(root, ".git"), 0700)
		} else {
			os.WriteFile(filepath.Join(root, ".git"), []byte("gitdir: elsewhere"), 0600)
		}
		if _, err := SourceHash(root); err == nil {
			t.Fatal("accepted .git metadata")
		}
	}
}
func TestSourceExportRejectsInvalidUTF8(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("raw byte filenames require POSIX")
	}
	for _, directory := range []bool{false, true} {
		for _, alias := range []bool{false, true} {
			root := t.TempDir()
			os.WriteFile(filepath.Join(root, "control"), []byte("control"), 0600)
			invalid := filepath.Join(root, string([]byte{0xff}))
			if directory {
				if err := os.Mkdir(invalid, 0700); err != nil {
					if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.EILSEQ) {
						t.Skip("host refuses invalid-byte filenames")
					}
					t.Fatal(err)
				}
				if alias {
					os.Mkdir(filepath.Join(root, "\ufffd"), 0700)
				}
			} else {
				if err := os.WriteFile(invalid, []byte("different bytes"), 0600); err != nil {
					if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.EILSEQ) {
						t.Skip("host refuses invalid-byte filenames")
					}
					t.Fatal(err)
				}
				if alias {
					os.WriteFile(filepath.Join(root, "\ufffd"), []byte("benign alias"), 0600)
				}
			}
			if _, err := SourceHash(root); err == nil {
				t.Fatalf("accepted invalid UTF-8: directory=%v alias=%v", directory, alias)
			}
		}
	}
}
func TestSourceExportKeepsUnsafeEntryRefusals(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX path and symlink control")
	}
	for _, name := range []string{"backslash", "symlink"} {
		root := t.TempDir()
		os.WriteFile(filepath.Join(root, "control"), []byte("x"), 0600)
		if name == "backslash" {
			os.WriteFile(filepath.Join(root, "a\\b"), []byte("x"), 0600)
		} else if err := os.Symlink(filepath.Join(root, "control"), filepath.Join(root, "link")); err != nil {
			t.Fatal(err)
		}
		if _, err := SourceHash(root); err == nil {
			t.Fatalf("accepted %s", name)
		}
	}
}

func TestSourceRootBoundary(t *testing.T) {
	root := t.TempDir()
	ordinary, nested := filepath.Join(root, "ordinary"), filepath.Join(root, ".git", "clean-export")
	for _, path := range []string{ordinary, nested} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "control.txt"), []byte("same source bytes\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := SourceHash(ordinary)
	if err != nil {
		t.Fatal(err)
	}
	got, err := SourceHash(nested)
	if err != nil || got != want {
		t.Fatalf("ancestor changed source binding: %s %v", got, err)
	}
	if _, err := SourceHash(filepath.Join(root, ".git")); err == nil {
		t.Fatal("metadata root accepted")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(ordinary, link); err != nil {
		t.Skipf("host cannot create symlink: %v", err)
	}
	if _, err := SourceHash(link); err == nil {
		t.Fatal("symlink root accepted")
	}
}

func TestSourceRootAliases(t *testing.T) {
	root := t.TempDir()
	metadata := filepath.Join(root, ".git")
	if err := os.MkdirAll(filepath.Join(metadata, "refs"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(metadata, "HEAD"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	prior, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chdir(metadata); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(prior); err != nil {
			t.Fatal(err)
		}
	}()
	for _, spelling := range []string{".", "refs/..", "refs/../."} {
		if _, err := SourceHash(spelling); err == nil {
			t.Errorf("metadata alias %q accepted", spelling)
		}
	}
	if err = os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	clean := filepath.Join(root, "clean")
	if err = os.Mkdir(clean, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(clean, "control"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	expected, err := SourceHash(clean)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chdir(clean); err != nil {
		t.Fatal(err)
	}
	got, err := SourceHash(".")
	if err != nil || got != expected {
		t.Fatalf("relative clean root changed: %s %v", got, err)
	}
}
