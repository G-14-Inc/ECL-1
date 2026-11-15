// ACS record completeness regressions. Robert F. Tilley Jr.; G-14, Inc.
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

func TestACSRecordCompleteness(t *testing.T) {
	path := filepath.Join("..", "..", "..", "tests", "fixtures", "acs-record-completeness", "cases.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Schema string
		Cases  []struct {
			Case                string
			Record              json.RawMessage
			ExpectedPublicRules []string `json:"expected_public_rules"`
			ExpectedDirectRules []string `json:"expected_direct_rules"`
			RequiredDirectPaths []string `json:"required_direct_paths"`
		}
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	rules := func(found []Finding) []string {
		seen := map[string]bool{}
		out := []string{}
		for _, f := range found {
			seen[f.RuleID] = true
		}
		for id := range seen {
			out = append(out, id)
		}
		sort.Strings(out)
		return out
	}
	for _, c := range manifest.Cases {
		t.Run(c.Case, func(t *testing.T) {
			value, err := strict.Parse(c.Record)
			if err != nil {
				t.Fatal(err)
			}
			direct, err := Findings(value.(map[string]any))
			if err != nil {
				t.Fatal(err)
			}
			if got := rules(direct); !reflect.DeepEqual(got, c.ExpectedDirectRules) {
				t.Fatalf("direct %v want %v: %+v", got, c.ExpectedDirectRules, direct)
			}
			for _, path := range c.RequiredDirectPaths {
				seen := false
				for _, f := range direct {
					if f.Path == path {
						seen = true
					}
				}
				if !seen {
					t.Fatalf("missing path %s: %+v", path, direct)
				}
			}
			found, err := EvaluateRecord(manifest.Schema, value)
			if err != nil {
				t.Fatal(err)
			}
			if got := rules(found); !reflect.DeepEqual(got, c.ExpectedPublicRules) {
				t.Fatalf("public %v want %v: %+v", got, c.ExpectedPublicRules, found)
			}
		})
	}
}
