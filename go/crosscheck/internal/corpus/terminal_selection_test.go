package corpus

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type terminalSelectionCase struct {
	ID            string   `json:"id"`
	Path          string   `json:"path"`
	SHA256        string   `json:"sha256"`
	Schema        string   `json:"schema"`
	Observed      []string `json:"observed"`
	Primary       *string  `json:"primary"`
	Secondary     []string `json:"secondary"`
	ErrorContains string   `json:"error_contains"`
}

func terminalSelectionManifest(t *testing.T) ([]terminalSelectionCase, []terminalSelectionCase) {
	t.Helper()
	var manifest struct {
		Records    []terminalSelectionCase `json:"record_cases"`
		Selections []terminalSelectionCase `json:"selection_cases"`
	}
	if err := decode(context().Root, "tests/fixtures/corpus-terminal-selection/manifest.json", &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest.Records, manifest.Selections
}

func TestTerminalRecordCorpusSelection(t *testing.T) {
	records, _ := terminalSelectionManifest(t)
	precedence, errors, err := registries(context().Root)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range records {
		t.Run(item.ID, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(context().Root, item.Path))
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(data)
			if hex.EncodeToString(digest[:]) != item.SHA256 {
				t.Fatal("fixture hash mismatch")
			}
			observed, err := Evaluate(data, Vector{ID: item.ID, Path: item.Path, Stage: "binding", Schema: item.Schema}, context())
			if err != nil {
				t.Fatal(err)
			}
			slices.Sort(observed)
			observed = slices.Compact(observed)
			if !slices.Equal(observed, item.Observed) {
				t.Fatalf("observed=%v; want %v", observed, item.Observed)
			}
			primary, secondary, err := selectFindings(observed, precedence, errors)
			if err != nil {
				t.Fatalf("observed=%v: %v", observed, err)
			}
			want := ""
			if item.Primary != nil {
				want = *item.Primary
			}
			if primary != want || !slices.Equal(secondary, item.Secondary) {
				t.Fatalf("observed=%v; primary=%q secondary=%v; want primary=%q secondary=%v", observed, primary, secondary, want, item.Secondary)
			}
			unchanged, err := os.ReadFile(filepath.Join(context().Root, item.Path))
			if err != nil || !slices.Equal(data, unchanged) {
				t.Fatal("fixture changed")
			}
		})
	}
}

func TestTerminalGenericFallbackSelectionBoundaries(t *testing.T) {
	_, cases := terminalSelectionManifest(t)
	precedence, errors, err := registries(context().Root)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range cases {
		t.Run(item.ID, func(t *testing.T) {
			reversed := slices.Clone(item.Observed)
			slices.Reverse(reversed)
			doubled := append(slices.Clone(item.Observed), item.Observed...)
			for _, observed := range [][]string{item.Observed, reversed, doubled} {
				primary, secondary, err := selectFindings(observed, precedence, errors)
				if item.ErrorContains != "" {
					if err == nil || !strings.Contains(err.Error(), item.ErrorContains) {
						t.Fatalf("expected %q, got %v", item.ErrorContains, err)
					}
					continue
				}
				if err != nil {
					t.Fatalf("observed=%v: %v", observed, err)
				}
				want := ""
				if item.Primary != nil {
					want = *item.Primary
				}
				if primary != want || !slices.Equal(secondary, item.Secondary) {
					t.Fatalf("observed=%v; primary=%q secondary=%v; want primary=%q secondary=%v", observed, primary, secondary, want, item.Secondary)
				}
			}
		})
	}
}
