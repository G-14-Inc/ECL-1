package documents_test

import (
	"encoding/json"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/documents"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/schema"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/semantic"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestWorkIntentContracts(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	for _, suite := range []string{"safe-state-declaration-contract", "work-intent-contract"} {
		raw, e := os.ReadFile(filepath.Join(root, "conformance", "suites", suite, "manifest.json"))
		if e != nil {
			t.Fatal(e)
		}
		var manifest struct {
			Vectors []struct {
				ID        string   `json:"id"`
				Path      string   `json:"path"`
				Schema    string   `json:"schema"`
				Stage     string   `json:"stage"`
				Expected  string   `json:"expected"`
				Primary   string   `json:"expected_primary_id"`
				Secondary []string `json:"expected_secondary_ids"`
			} `json:"vectors"`
		}
		if e = json.Unmarshal(raw, &manifest); e != nil {
			t.Fatal(e)
		}
		for _, row := range manifest.Vectors {
			t.Run(row.ID, func(t *testing.T) {
				raw, e := os.ReadFile(filepath.Join(root, row.Path))
				if e != nil {
					t.Fatal(e)
				}
				value, e := strict.Parse(raw)
				if e != nil {
					t.Fatal(e)
				}
				original, _ := json.Marshal(value)
				var found []semantic.Finding
				if row.Stage == "document" {
					found, e = documents.Evaluate(row.Schema, value)
					if e != nil {
						t.Fatal(e)
					}
				} else {
					found = semantic.SafeStateProfile(value)
					errors, e := schema.ECL().Errors(row.Schema, value, 1)
					if e != nil {
						t.Fatal(e)
					}
					if len(errors) > 0 {
						found = append(found, semantic.Finding{RuleID: "ecl.error.schema-invalid.v1"})
					}
				}
				set := map[string]bool{}
				for _, f := range found {
					set[f.RuleID] = true
				}
				actual := []string{}
				for id := range set {
					actual = append(actual, id)
				}
				sort.Strings(actual)
				expected := []string{}
				if row.Expected == "fail" {
					expected = append(expected, row.Primary)
					expected = append(expected, row.Secondary...)
				}
				sort.Strings(expected)
				if !reflect.DeepEqual(actual, expected) {
					t.Fatalf("got %v, want %v; %+v", actual, expected, found)
				}
				after, _ := json.Marshal(value)
				if string(after) != string(original) {
					t.Fatal("input mutated")
				}
			})
		}
	}
}
