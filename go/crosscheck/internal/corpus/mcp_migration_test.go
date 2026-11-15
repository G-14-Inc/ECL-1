package corpus

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestMCPMigratedCorpus checks exact registry-selected primary and secondary findings.
func TestMCPMigratedCorpus(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..")
	precedence, errors, err := registries(root)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "conformance/suites/mcp-gateway/manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Vectors []Vector `json:"vectors"`
	}
	if err = json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, vector := range manifest.Vectors {
		if vector.Stage != "binding" {
			continue
		}
		t.Run(vector.ID, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, vector.Path))
			if err != nil {
				t.Fatal(err)
			}
			found, err := Evaluate(data, vector, &Context{Root: root})
			if err != nil {
				t.Fatal(err)
			}
			if (len(found) == 0) != (vector.Expected == "pass") {
				t.Fatalf("expected %s: %v", vector.Expected, found)
			}
			primary, secondary, err := selectFindings(found, precedence, errors)
			if err != nil {
				t.Fatal(err)
			}
			if primary != vector.Primary || !slices.Equal(secondary, vector.Secondary) {
				t.Fatalf("primary=%q secondary=%v; want primary=%q secondary=%v", primary, secondary, vector.Primary, vector.Secondary)
			}
		})
	}
}
