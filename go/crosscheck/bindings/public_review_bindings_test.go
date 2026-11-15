package bindings

import (
	"encoding/json"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/validatorx"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/schema"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestPublicReviewBindingsCorpus(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	raw, err := os.ReadFile(filepath.Join(root, "conformance/suites/repair-bindings/manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Vectors []struct {
			ID, Path, Schema, Stage, Expected string
			Primary                           string   `json:"expected_primary_id"`
			Secondary                         []string `json:"expected_secondary_ids"`
		}
	}
	if err = json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, v := range manifest.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, v.Path))
			if err != nil {
				t.Fatal(err)
			}
			value, err := strict.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			ids := map[string]bool{}
			if v.Stage == "binding" {
				found, err := EvaluateRecordWithKeys(v.Schema, value, nil)
				if err != nil {
					t.Fatal(err)
				}
				for _, f := range found {
					ids[f.RuleID] = true
				}
			} else {
				errors, err := schema.Validate(v.Schema, value)
				if err != nil {
					t.Fatal(err)
				}
				if len(errors) > 0 {
					ids[schemaInvalid] = true
				}
				for _, f := range validatorx.Validate(value) {
					ids[f.RuleID] = true
				}
			}
			actual := []string{}
			for id := range ids {
				actual = append(actual, id)
			}
			sort.Strings(actual)
			expected := []string{}
			if v.Expected == "fail" {
				expected = append(expected, v.Primary)
				expected = append(expected, v.Secondary...)
			}
			sort.Strings(expected)
			if !reflect.DeepEqual(actual, expected) {
				t.Fatalf("got %v want %v", actual, expected)
			}
		})
	}
}
func TestPublicReviewDirectAdvisoryProofConflict(t *testing.T) {
	value := map[string]any{"dependencies": []any{map[string]any{"class": "advisory", "supplies_required_proof": true, "loss_disposition": "fail_closed"}}}
	for _, f := range validatorx.Validate(value) {
		if f.RuleID == validatorx.ClassificationRule {
			return
		}
	}
	t.Fatal("missing advisory/proof classification finding")
}
