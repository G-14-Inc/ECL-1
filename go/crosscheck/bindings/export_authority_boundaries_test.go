// Telemetry and sender-constraint boundaries. Robert F. Tilley Jr.; G-14, Inc.
package bindings

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
)

func TestExportAuthorityBoundaries(t *testing.T) {
	root := filepath.Join("..", "..", "..", "tests", "fixtures", "export-authority-boundaries")
	raw, err := os.ReadFile(filepath.Join(root, "export-keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := LoadExportKeys(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Cases []struct {
			ID, File, Schema string
			Expected         []string `json:"expected_rules"`
		}
	}
	if err = json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, item := range manifest.Cases {
		t.Run(item.ID, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, item.File))
			if err != nil {
				t.Fatal(err)
			}
			value, err := strict.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			original, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			findings, err := EvaluateRecordWithKeys(item.Schema, value, keys)
			if err != nil {
				t.Fatal(err)
			}
			rules, seen := []string{}, map[string]bool{}
			for _, finding := range findings {
				if !seen[finding.RuleID] {
					seen[finding.RuleID] = true
					rules = append(rules, finding.RuleID)
				}
			}
			sort.Strings(rules)
			if !reflect.DeepEqual(rules, item.Expected) {
				t.Fatalf("got %v want %v: %+v", rules, item.Expected, findings)
			}
			after, err := json.Marshal(value)
			if err != nil || string(after) != string(original) {
				t.Fatal("input changed", err)
			}
		})
	}
}
