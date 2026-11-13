package semantic_test

import (
	"encoding/json"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/semantic"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
	"os"
	"path/filepath"
	"testing"
)

func TestCoreContractRegressions(t *testing.T) {
	root := filepath.Join("..", "..", "..", "tests", "fixtures", "core-contract-regressions")
	read := func(name string) []byte {
		b, e := os.ReadFile(filepath.Join(root, name))
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	var manifest struct {
		Cases []struct {
			ID, File, Kind   string
			Mutation         *string
			Required, Absent []string
		}
	}
	if e := json.Unmarshal(read("manifest.json"), &manifest); e != nil {
		t.Fatal(e)
	}
	for _, row := range manifest.Cases {
		t.Run(row.ID, func(t *testing.T) {
			value, e := strict.Parse(read(row.File))
			if e != nil {
				t.Fatal(e)
			}
			if row.Mutation != nil && *row.Mutation == "fractional_parameter" {
				value.(map[string]any)["action"].(map[string]any)["parameters"] = map[string]any{"number": 1.5}
			}
			before, _ := json.Marshal(value)
			var found []semantic.Finding
			if row.Kind == "safe-state" {
				found = semantic.SafeStateProfile(value)
			} else {
				found, e = semantic.Validate(value, semantic.Registered())
				if e != nil {
					t.Fatal(e)
				}
			}
			rules := map[string]bool{}
			for _, f := range found {
				rules[f.RuleID] = true
			}
			for _, rule := range row.Required {
				if !rules[rule] {
					t.Errorf("missing %s: %+v", rule, found)
				}
			}
			for _, rule := range row.Absent {
				if rules[rule] {
					t.Errorf("unexpected %s: %+v", rule, found)
				}
			}
			after, _ := json.Marshal(value)
			if string(before) != string(after) {
				t.Fatal("input mutated")
			}
		})
	}
}
