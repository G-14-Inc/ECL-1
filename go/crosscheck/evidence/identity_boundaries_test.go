package evidence_test

import (
	"bytes"
	"encoding/json"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
	"reflect"
	"sort"
	"testing"
)

func TestCausalIdentityBoundaries(t *testing.T) {
	var doc struct {
		Causal []struct {
			Name     string   `json:"name"`
			Records  []any    `json:"records"`
			Members  []string `json:"identifier_members"`
			Expected struct {
				Status   string   `json:"status"`
				Terminal []string `json:"terminal"`
				Open     []string `json:"open"`
				Rules    []string `json:"rules"`
			} `json:"expected"`
		} `json:"causal"`
	}
	if err := json.Unmarshal(vectors.Read(t, "tests/fixtures/identity-boundaries/cases.json"), &doc); err != nil {
		t.Fatal(err)
	}
	// Decode numeric workflow sequences in the same domain as the strict JSON parser.
	var raw map[string]any
	decoder := json.NewDecoder(bytes.NewReader(vectors.Read(t, "tests/fixtures/identity-boundaries/cases.json")))
	decoder.UseNumber()
	if err := decoder.Decode(&raw); err != nil {
		t.Fatal(err)
	}
	for i, row := range doc.Causal {
		t.Run(row.Name, func(t *testing.T) {
			records := raw["causal"].([]any)[i].(map[string]any)["records"].([]any)
			members := row.Members
			if members == nil {
				members = []string{"object_id"}
			}
			got, err := evidence.AnalyzeGraph(records, nil, evidence.MaxRecords, evidence.MaxPredecessors, members, false)
			if err != nil {
				t.Fatal(err)
			}
			rules := []string{}
			seen := map[string]bool{}
			for _, f := range got.Findings {
				if !seen[f.RuleID] {
					rules = append(rules, f.RuleID)
					seen[f.RuleID] = true
				}
			}
			sort.Strings(rules)
			if got.Status != row.Expected.Status || !reflect.DeepEqual(got.TerminalActionIDs, row.Expected.Terminal) || !reflect.DeepEqual(got.OpenActionIDs, row.Expected.Open) || !reflect.DeepEqual(rules, row.Expected.Rules) {
				t.Fatalf("status=%s terminal=%v open=%v rules=%v; want %+v", got.Status, got.TerminalActionIDs, got.OpenActionIDs, rules, row.Expected)
			}
		})
	}
}
