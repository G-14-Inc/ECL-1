package documents_test

import (
	"encoding/json"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/documents"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestClaimDeploymentContracts(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	for _, suite := range []string{"claim-deployment-contract", "deployment-timing-case"} {
		raw, e := os.ReadFile(filepath.Join(root, "conformance", "suites", suite, "manifest.json"))
		if e != nil {
			t.Fatal(e)
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
		if e = json.Unmarshal(raw, &manifest); e != nil {
			t.Fatal(e)
		}
		for _, row := range manifest.Vectors {
			t.Run(row.ID, func(t *testing.T) {
				raw, e := os.ReadFile(filepath.Join(root, row.Path))
				if e != nil {
					t.Fatal(e)
				}
				v, e := strict.Parse(raw)
				if e != nil {
					t.Fatal(e)
				}
				found, e := documents.Evaluate(row.Schema, v)
				if e != nil {
					t.Fatal(e)
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
					t.Fatalf("%v, want %v; %+v", actual, expected, found)
				}
			})
		}
	}
}
func TestParsedDeploymentTimingTypes(t *testing.T) {
	raw, e := os.ReadFile(filepath.Join("..", "..", "..", "conformance", "suites", "document-coverage", "deployment-valid-federated-example.json"))
	if e != nil {
		t.Fatal(e)
	}
	for _, invalid := range []any{true, "1", nil, json.Number("1.5"), math.NaN(), math.Inf(1)} {
		v, e := strict.Parse(raw)
		if e != nil {
			t.Fatal(e)
		}
		v.(map[string]any)["timing_case"].(map[string]any)["federated_exchange_seconds"] = invalid
		found, e := documents.Evaluate("https://externalcontrollayer.ai/ns/schema/deployment-profile/1", v)
		if e != nil {
			t.Fatal(e)
		}
		schema := false
		for _, f := range found {
			if f.RuleID == "ecl.error.schema-invalid.v1" {
				schema = true
			}
			if f.RuleID == "ecl.rule.deployment-timing-case-consistent.v1" {
				t.Fatalf("unreadable value compared: %+v", found)
			}
		}
		if !schema {
			t.Fatalf("invalid interval accepted: %v", invalid)
		}
	}
}
