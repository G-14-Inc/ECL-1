package semantic_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/schema"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
)

func TestNamespaceReservation(t *testing.T) {
	root := filepath.Join("..", "..", "..", "tests", "fixtures")
	raw, err := os.ReadFile(filepath.Join(root, "namespace-reservation-cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name, Identifier string
		Reserved         bool
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(filepath.Join(root, "extension-consumer-cases", "request-control.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range cases {
		for _, critical := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/critical=%v", row.Name, critical), func(t *testing.T) {
				parsed, err := strict.Parse(original)
				if err != nil {
					t.Fatal(err)
				}
				value := parsed.(map[string]any)
				value["extensions"] = []any{map[string]any{"id": row.Identifier, "version": json.Number("1"), "critical": critical, "value": map[string]any{"grant_authority": true}}}
				before, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				found, err := schema.ECL().Errors("https://externalcontrollayer.ai/ns/schema/dcmp/2", value, 100)
				if err != nil {
					t.Fatal(err)
				}
				if (len(found) == 0) == row.Reserved {
					t.Fatalf("schema result: %+v; reserved=%v", found, row.Reserved)
				}
				findings, err := evidence.ObjectFindings(value)
				if err != nil {
					t.Fatal(err)
				}
				seen := map[string]bool{}
				for _, finding := range findings {
					seen[finding.RuleID] = true
				}
				got, want := []string{}, []string{}
				for id := range seen {
					got = append(got, id)
				}
				if row.Reserved {
					want = append(want, "ecl.error.schema-invalid.v1", "ecl.rule.extension-namespace-allocated.v1")
				}
				if critical {
					want = append(want, "ecl.rule.unknown-critical-extension-rejected.v1")
				}
				sort.Strings(got)
				sort.Strings(want)
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("got %v, want %v", got, want)
				}
				after, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if string(before) != string(after) {
					t.Fatal("identifier or input changed")
				}
			})
		}
	}
}
