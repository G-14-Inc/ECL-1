package schema_test

import (
	"encoding/json"
	"os"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/bindings"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/schema"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/semantic"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/trust"
)

func TestSchemaContractBoundaries(t *testing.T) {
	data, err := os.ReadFile("../../../tests/fixtures/schema-contract-boundaries.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		ID, Lane, Schema, Verdict string
		Primary                   *string
		Value                     json.RawMessage
		Valid                     bool
		Rules                     []string
	}
	if err = json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile("../../../conformance/fixtures/evidence/trust-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := trust.Load(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			value, err := strict.Parse(c.Value)
			if err != nil {
				t.Fatal(err)
			}
			if c.Lane == "bundle" {
				report, e := evidence.Verify(value, policy, evidence.Options{Now: "2026-10-01T00:00:00Z"})
				if e != nil {
					t.Fatal(e)
				}
				got := evidence.PrimaryFinding(report)
				samePrimary := got == nil && c.Primary == nil || got != nil && c.Primary != nil && *got == *c.Primary
				if report.Verdict != c.Verdict || !samePrimary {
					t.Fatalf("verdict=%s primary=%v, want %s %v", report.Verdict, got, c.Verdict, c.Primary)
				}
				return
			}
			valid, e := schema.ECL().Valid(c.Schema, value)
			if e != nil || valid != c.Valid {
				t.Fatalf("valid=%v want=%v err=%v", valid, c.Valid, e)
			}
			if c.Lane == "adapter" {
				findings, e := semantic.Validate(value, semantic.Registered())
				if e != nil {
					t.Fatal(e)
				}
				actual := map[string]bool{}
				for _, f := range findings {
					actual[f.RuleID] = true
				}
				if len(actual) != len(c.Rules) {
					t.Fatalf("rules=%v want=%v", actual, c.Rules)
				}
				for _, id := range c.Rules {
					if !actual[id] {
						t.Fatalf("missing rule %s: %v", id, actual)
					}
				}
			} else if c.Lane == "binding" && c.Valid {
				findings, e := bindings.EvaluateRecord(c.Schema, value)
				if e != nil || len(findings) != 0 {
					t.Fatalf("findings=%v err=%v", findings, e)
				}
			}
		})
	}
}
