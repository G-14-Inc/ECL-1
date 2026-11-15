package bindings_test

import (
	"bytes"
	"encoding/json"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/bindings"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
	"reflect"
	"sort"
	"testing"
)

func TestOAuthKeySelection(t *testing.T) {
	var rows []struct {
		Name     string         `json:"name"`
		Record   map[string]any `json:"record"`
		Expected []string       `json:"expected_rules"`
	}
	decoder := json.NewDecoder(bytes.NewReader(vectors.Read(t, "tests/fixtures/oauth-key-selection/cases.json")))
	decoder.UseNumber()
	if err := decoder.Decode(&rows); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		t.Run(row.Name, func(t *testing.T) {
			for _, gated := range []bool{false, true} {
				var found []bindings.Finding
				var err error
				if gated {
					found, err = bindings.EvaluateRecord("https://externalcontrollayer.ai/ns/schema/binding/oauth-presentation/1", row.Record)
				} else {
					found, err = bindings.Findings(row.Record)
				}
				if err != nil {
					t.Fatal(err)
				}
				actual := []string{}
				seen := map[string]bool{}
				for _, finding := range found {
					if !seen[finding.RuleID] {
						actual = append(actual, finding.RuleID)
						seen[finding.RuleID] = true
					}
				}
				sort.Strings(actual)
				if !reflect.DeepEqual(actual, row.Expected) {
					t.Fatalf("gated=%t got %v want %v", gated, actual, row.Expected)
				}
			}
		})
	}
}
