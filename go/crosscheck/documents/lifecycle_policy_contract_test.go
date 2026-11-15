package documents_test

import (
	"encoding/json"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/documents"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLifecyclePolicyContract(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	raw, err := os.ReadFile(filepath.Join(root, "conformance/suites/lifecycle-policy-contract/manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Vectors []struct {
			ID        string   `json:"id"`
			Path      string   `json:"path"`
			Schema    string   `json:"schema"`
			Expected  string   `json:"expected"`
			Primary   string   `json:"expected_primary_id"`
			Secondary []string `json:"expected_secondary_ids"`
		} `json:"vectors"`
	}
	if err = json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, row := range manifest.Vectors {
		t.Run(row.ID, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, row.Path))
			if err != nil {
				t.Fatal(err)
			}
			value, err := strict.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			original, _ := json.Marshal(value)
			found, err := documents.Evaluate(row.Schema, value)
			if err != nil {
				t.Fatal(err)
			}
			actual := []string{}
			for _, f := range found {
				actual = append(actual, f.RuleID)
			}
			expected := []string{}
			if row.Expected == "fail" {
				expected = append(expected, row.Primary)
				expected = append(expected, row.Secondary...)
			}
			if !reflect.DeepEqual(actual, expected) {
				t.Fatalf("got %v, want %v; %+v", actual, expected, found)
			}
			after, _ := json.Marshal(value)
			if string(original) != string(after) {
				t.Fatal("input mutated")
			}
		})
	}
}
