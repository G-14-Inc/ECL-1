package evidence_test

import (
	"encoding/json"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/canon"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestPublicReviewCausalOrigins(t *testing.T) {
	var cases []struct {
		Name       string          `json:"name"`
		Records    json.RawMessage `json:"records"`
		Status     string          `json:"status"`
		Rules      []string        `json:"expected_rules"`
		Unresolved []string        `json:"expected_unresolved"`
		External   []string        `json:"allowed_external_predecessors"`
		Bundle     string          `json:"bundle_path"`
		Verdict    string          `json:"expected_verdict"`
		Primary    string          `json:"expected_primary"`
	}
	if err := json.Unmarshal(vectors.Read(t, "tests/fixtures/repair-causal-origin.json"), &cases); err != nil {
		t.Fatal(err)
	}
	policy := load(t, "conformance/suites/evidence-bundle/trust-policy.json")
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			value, err := strict.Parse(c.Records)
			if err != nil {
				t.Fatal(err)
			}
			external := map[string]bool{}
			for _, id := range c.External {
				external[id] = true
			}
			graph, err := evidence.AnalyzeGraph(value.([]any), external, 1000, 128, []string{"object_id"}, true)
			if err != nil {
				t.Fatal(err)
			}
			rules := []string{}
			for _, f := range graph.Findings {
				rules = append(rules, f.RuleID)
			}
			slices.Sort(rules)
			rules = slices.Compact(rules)
			if graph.Status != c.Status || !slices.Equal(rules, c.Rules) || !slices.Equal(graph.UnresolvedPredecessorIDs, c.Unresolved) {
				t.Fatalf("graph %+v; want %s %v %v", graph, c.Status, c.Rules, c.Unresolved)
			}
			bundle, err := strict.Parse(vectors.Read(t, c.Bundle))
			if err != nil {
				t.Fatal(err)
			}
			report, err := evidence.Verify(bundle, policy, evidence.Options{Now: "2026-10-01T00:00:00Z"})
			if err != nil {
				t.Fatal(err)
			}
			primary := ""
			if p := evidence.PrimaryFinding(report); p != nil {
				primary = *p
			}
			if report.Verdict != c.Verdict || primary != c.Primary {
				t.Fatalf("report %+v; want %s %s", report, c.Verdict, c.Primary)
			}
			if slices.Contains(report.Scope.Established, "causal-completeness") != (c.Verdict == "verified") {
				t.Fatalf("scope %+v", report.Scope)
			}
			for _, e := range report.EnvelopeChecks {
				if e.Historical != "valid" || e.Current != "valid" {
					t.Fatalf("envelope %+v", e)
				}
			}
		})
	}
}
func originMinimal(t *testing.T, id, wf string, sequence int, prior map[string]any, parent string) map[string]any {
	t.Helper()
	w := map[string]any{"workflow_id": wf, "root_trace_id": "urn:trace", "attempt": json.Number("1"), "sequence": json.Number(fmt.Sprint(sequence)), "causal_predecessors": []any{}}
	if parent != "" {
		w["parent_workflow_id"] = parent
	}
	if prior != nil {
		digest, err := canon.Digest(prior)
		if err != nil {
			t.Fatal(err)
		}
		w["causal_predecessors"] = []any{map[string]any{"id": prior["object_id"], "digest": map[string]any{"algorithm": "ecl.digest.sha-256.v1", "value": digest}}}
	}
	return map[string]any{"object_id": id, "workflow": w}
}
func TestCausalOriginDeepProgression(t *testing.T) {
	start := originMinimal(t, "urn:parent:0", "urn:parent", 0, nil, "")
	records := []any{start}
	prior := start
	for n := 0; n < 2048; n++ {
		child := originMinimal(t, fmt.Sprintf("urn:child:%04d", n), "urn:child", n, prior, "urn:parent")
		records = append(records, child, originMinimal(t, fmt.Sprintf("urn:join:%04d", n), "urn:parent", n+1, child, ""))
		prior = child
	}
	slices.Reverse(records)
	result, err := evidence.AnalyzeGraph(records, nil, 5000, 128, []string{"object_id"}, true)
	if err != nil || result.Status != "complete" || len(result.Findings) != 0 {
		t.Fatalf("%+v %v", result, err)
	}
}
func TestCycleNormalizationDiagnostic(t *testing.T) {
	for _, length := range []int{3, 2048} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			names := make([]string, length)
			records := make([]any, length)
			for n := range names {
				names[n] = fmt.Sprintf("urn:cycle:%04d", n)
				records[n] = originMinimal(t, names[n], "urn:cycle", n, nil, "")
			}
			for n, r := range records {
				r.(map[string]any)["workflow"].(map[string]any)["causal_predecessors"] = []any{map[string]any{"id": names[(n+1)%length], "digest": map[string]any{"algorithm": "ecl.digest.sha-256.v1", "value": strings.Repeat("0", 64)}}}
			}
			for pass := 0; pass < 2; pass++ {
				result, err := evidence.Analyze(records, nil, 3000, 128)
				if err != nil {
					t.Fatal(err)
				}
				cycles := []evidence.Finding{}
				for _, f := range result.Findings {
					if f.RuleID == "ecl.rule.bundle-causal-graph-acyclic.v1" {
						cycles = append(cycles, f)
					}
				}
				display := append(append([]string{}, names...), names[0])
				if len(display) > 18 {
					display = append(append(append([]string{}, display[:8]...), "..."), display[len(display)-8:]...)
				}
				if len(cycles) != 1 || cycles[0].Detail != "causal cycle: "+strings.Join(display, " -> ") {
					t.Fatalf("cycles %+v", cycles)
				}
				slices.Reverse(records)
			}
		})
	}
}
