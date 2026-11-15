// Authentication record regressions. Robert F. Tilley Jr.; G-14, Inc.
package bindings

import (
	"encoding/json"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestAuthenticationRecords(t *testing.T) {
	root := filepath.Join("..", "..", "..", "tests", "fixtures", "authentication-boundaries")
	raw, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Cases []struct {
			Case, Path, Schema, Message string
			ExpectedRules               []string `json:"expected_rules"`
			RequiredPaths               []string `json:"required_paths"`
		}
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, c := range manifest.Cases {
		t.Run(c.Case, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, c.Path))
			if err != nil {
				t.Fatal(err)
			}
			value, err := strict.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			found, err := EvaluateRecord(c.Schema, value)
			if err != nil {
				t.Fatal(err)
			}
			seen := map[string]bool{}
			rules := []string{}
			paths := map[string]bool{}
			message := c.Message == ""
			for _, f := range found {
				seen[f.RuleID] = true
				paths[f.Path] = true
				if f.Detail == c.Message {
					message = true
				}
			}
			for id := range seen {
				rules = append(rules, id)
			}
			sort.Strings(rules)
			if !reflect.DeepEqual(rules, c.ExpectedRules) {
				t.Fatalf("got %v want %v: %+v", rules, c.ExpectedRules, found)
			}
			if !message {
				t.Fatalf("missing diagnostic %q: %+v", c.Message, found)
			}
			for _, path := range c.RequiredPaths {
				if !paths[path] {
					t.Fatalf("missing path %s: %+v", path, found)
				}
			}
		})
	}
}

func TestNativeDeferZeroDeadline(t *testing.T) {
	record := map[string]any{"guardian": map[string]any{"observed_at": "2026-09-30T09:00:00.080000Z", "result": map[string]any{"defer_details": map[string]any{"resolution_timeout_ms": json.Number("0")}}}}
	result := acsDeadline(record, "defer")
	if result == nil || result.String() != "1790758800080000000" {
		t.Fatalf("zero DEFER: %v", result)
	}
}
