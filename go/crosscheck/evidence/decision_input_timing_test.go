package evidence_test

import (
	"encoding/json"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/trust"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

func TestDecisionInputTimingScope(t *testing.T) {
	root := filepath.Join("..", "..", "..", "tests", "fixtures", "decision-input-timing")
	read := func(name string) []byte {
		b, e := os.ReadFile(filepath.Join(root, name))
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	parse := func(name string) map[string]any {
		x, e := strict.Parse(read(name))
		if e != nil {
			t.Fatal(e)
		}
		return x.(map[string]any)
	}
	var m struct {
		Now   string
		Cases []struct {
			ID, Bundle, Verdict, Scope string
			Register                   *string
		}
	}
	if e := json.Unmarshal(read("manifest.json"), &m); e != nil {
		t.Fatal(e)
	}
	policy, e := trust.Load(read("policy.json"))
	if e != nil {
		t.Fatal(e)
	}
	for _, row := range m.Cases {
		t.Run(row.ID, func(t *testing.T) {
			opts := evidence.Options{Now: m.Now}
			if row.Register != nil {
				opts.Register = parse(*row.Register)
			}
			report, e := evidence.Verify(parse(row.Bundle), policy, opts)
			if e != nil {
				t.Fatal(e)
			}
			if report.Verdict != row.Verdict {
				t.Fatalf("%s: %+v", report.Verdict, report.Findings)
			}
			const scope = "decision-input-timing"
			if slices.Contains(report.Scope.Established, scope) != (row.Scope == "established") {
				t.Errorf("established: %+v", report.Scope)
			}
			if slices.Contains(report.Scope.NotEstablished, scope) != (row.Scope == "missing" || row.Scope == "not-established") {
				t.Errorf("not-established: %+v", report.Scope)
			}
			reason := ""
			if row.Scope == "missing" {
				reason = "input-times-not-recorded"
			}
			if report.Scope.Reasons[scope] != reason {
				t.Errorf("reasons: %+v", report.Scope)
			}
			if slices.Contains(report.Scope.Established, "recorded-times-true") {
				t.Fatal("timestamps asserted true")
			}
			if row.Scope == "established" && !reflect.DeepEqual(report.Scope.Checks[scope].Objects, []int{1}) {
				t.Errorf("objects: %+v", report.Scope.Checks[scope])
			}
		})
	}
	data, e := strict.Parse(read("helper-cases.json"))
	if e != nil {
		t.Fatal(e)
	}
	for _, raw := range data.([]any) {
		row := raw.(map[string]any)
		t.Run(row["id"].(string), func(t *testing.T) {
			a, c := evidence.TimingCoverage(row["basis"].(map[string]any), row["register"].(map[string]any), "ecl.action.ai-proposed-operation.v1", "2026-09-29T10:00:00Z")
			expected := row["expected"].([]any)
			if a != expected[0] || c != expected[1] {
				t.Errorf("%v %v, want %v", a, c, expected)
			}
		})
	}
}
