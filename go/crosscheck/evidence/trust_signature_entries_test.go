package evidence_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/vectors"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/trust"
)

func TestSignatureEntryTimesAndAttestationPolicy(t *testing.T) {
	var cases []struct {
		ID       string          `json:"id"`
		Bundle   json.RawMessage `json:"bundle"`
		Policy   json.RawMessage `json:"policy"`
		Now      string          `json:"now"`
		Expected struct {
			Verdict      string           `json:"verdict"`
			Primary      any              `json:"primary"`
			Dependencies []map[string]any `json:"dependencies"`
		} `json:"expected"`
	}
	if err := json.Unmarshal(vectors.Read(t, "tests/fixtures/trust-signature-entry.json"), &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			policy, err := trust.Load(c.Policy)
			if err != nil {
				t.Fatal(err)
			}
			bundle, err := strict.Parse(c.Bundle)
			if err != nil {
				t.Fatal(err)
			}
			report, err := evidence.Verify(bundle, policy, evidence.Options{Now: c.Now})
			if err != nil {
				t.Fatal(err)
			}
			// Normalize report and expected JSON number representations for field comparison.
			raw, err := json.Marshal(report.JSON())
			if err != nil {
				t.Fatal(err)
			}
			var value map[string]any
			if err := json.Unmarshal(raw, &value); err != nil {
				t.Fatal(err)
			}
			if value["verdict"] != c.Expected.Verdict || !reflect.DeepEqual(value["primary"], c.Expected.Primary) {
				t.Fatalf("verdict/primary: %v / %v", value["verdict"], value["primary"])
			}
			for _, want := range c.Expected.Dependencies {
				var matches []map[string]any
				for _, entry := range value["trust_dependencies"].([]any) {
					d := entry.(map[string]any)
					if d["index"] == want["index"] && d["role"] == want["role"] {
						matches = append(matches, d)
					}
				}
				position := int(want["occurrence"].(float64))
				if position >= len(matches) {
					t.Fatalf("missing dependency %v", want)
				}
				for key, expected := range want {
					if key != "occurrence" && !reflect.DeepEqual(matches[position][key], expected) {
						t.Fatalf("dependency %v: %s got %v want %v", want, key, matches[position][key], expected)
					}
				}
			}
		})
	}
}
