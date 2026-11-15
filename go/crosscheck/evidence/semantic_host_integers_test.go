package evidence_test

import (
	"bytes"
	"encoding/json"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/documents"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/validatorx"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
	"os"
	"reflect"
	"sort"
	"testing"
)

func TestSchemaIntegerParsedAPIs(t *testing.T) {
	raw, err := os.ReadFile("../../../tests/fixtures/semantic-host-integers/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		ID, API  string
		Value    json.RawMessage
		Required []string
		Clean    bool
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			var baseline []string
			for _, mode := range []string{"strict", "unmarshal", "use-number-decimal", "use-number-exponent"} {
				t.Run(mode, func(t *testing.T) {
					var value any
					if mode == "strict" {
						var err error
						value, err = strict.Parse(c.Value)
						if err != nil {
							t.Fatal(err)
						}
					} else if mode == "unmarshal" {
						if err := json.Unmarshal(c.Value, &value); err != nil {
							t.Fatal(err)
						}
					} else {
						decoder := json.NewDecoder(bytes.NewReader(c.Value))
						decoder.UseNumber()
						if err := decoder.Decode(&value); err != nil {
							t.Fatal(err)
						}
						suffix := ".0"
						if mode == "use-number-exponent" {
							suffix = "e0"
						}
						var transform func(any) any
						transform = func(v any) any {
							switch x := v.(type) {
							case json.Number:
								return json.Number(x.String() + suffix)
							case []any:
								for i := range x {
									x[i] = transform(x[i])
								}
								return x
							case map[string]any:
								for k := range x {
									x[k] = transform(x[k])
								}
								return x
							default:
								return v
							}
						}
						value = transform(value)
					}
					before, err := json.Marshal(value)
					if err != nil {
						t.Fatal(err)
					}
					keys := []string{}
					rules := map[string]bool{}
					add := func(rule, path string) { keys = append(keys, rule+"@"+path); rules[rule] = true }
					if c.API == "deployment" {
						findings, e := documents.Evaluate("https://externalcontrollayer.ai/ns/schema/deployment-profile/1", value)
						if e != nil {
							t.Fatal(e)
						}
						for _, f := range findings {
							add(f.RuleID, f.Path)
						}
					} else {
						findings, e := evidence.ObjectFindings(value)
						if e != nil {
							t.Fatal(e)
						}
						for _, f := range findings {
							add(f.RuleID, f.Path)
						}
					}
					sort.Strings(keys)
					for _, rule := range c.Required {
						if !rules[rule] {
							t.Errorf("missing %s: %v", rule, keys)
						}
					}
					if c.Clean && len(keys) != 0 {
						t.Errorf("valid control: %v", keys)
					}
					if mode == "strict" {
						baseline = keys
					} else if !reflect.DeepEqual(keys, baseline) {
						t.Errorf("integer representation changed findings: %v != %v", keys, baseline)
					}
					after, err := json.Marshal(value)
					if err != nil || !bytes.Equal(before, after) {
						t.Fatal("input mutated", err)
					}
				})
			}
		})
	}
}

func TestTimingCoverageUnmarshaledIntegerConstraints(t *testing.T) {
	raw, err := os.ReadFile("../../../tests/fixtures/decision-input-timing/helper-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		ID              string
		Basis, Register map[string]any
		Expected        []bool
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			before, err := json.Marshal(c.Register)
			if err != nil {
				t.Fatal(err)
			}
			a, complete := evidence.TimingCoverage(c.Basis, c.Register, "ecl.action.ai-proposed-operation.v1", "2026-09-29T10:00:00Z")
			if a != c.Expected[0] || complete != c.Expected[1] {
				t.Errorf("got %v,%v; want %v", a, complete, c.Expected)
			}
			after, err := json.Marshal(c.Register)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("register mutated", err)
			}
		})
	}
}

func TestSharedExtensionSelectorIntegerVersions(t *testing.T) {
	for _, c := range []struct {
		protocol string
		version  any
		want     bool
	}{
		{"EBMP-2", int(1), true}, {"EBMP-2", float64(1), true},
		{"EBMP-2", json.Number("1.0"), true}, {"EBMP-2", json.Number("1e0"), true},
		{"DCMP-2", float64(1), false}, {"EBMP-2", float64(2), false},
		{"EBMP-2", true, false}, {"EBMP-2", float64(1.5), false},
	} {
		root := map[string]any{"protocol": c.protocol}
		occurrence := map[string]any{"id": "ecl.ext.outcome-reason.v1", "version": c.version}
		before, err := json.Marshal(occurrence)
		if err != nil {
			t.Fatal(err)
		}
		if got := validatorx.InterpretedOccurrence(root, occurrence); got != c.want {
			t.Errorf("%s %T(%v): got%v", c.protocol, c.version, c.version, got)
		}
		after, err := json.Marshal(occurrence)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("occurrence mutated", err)
		}
	}
}
