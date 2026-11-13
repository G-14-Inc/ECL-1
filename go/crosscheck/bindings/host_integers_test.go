// Retained binding counter and bound regressions. Robert F. Tilley Jr.; G-14, Inc.
package bindings_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/bindings"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/schema"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
)

func hostIntegerClone(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, v := range x {
			out[k] = hostIntegerClone(v)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, v := range x {
			out[i] = hostIntegerClone(v)
		}
		return out
	default:
		return v
	}
}
func hostIntegerSet(v any, path []string, replacement any) {
	at := v.(map[string]any)
	for _, key := range path[:len(path)-1] {
		at = at[key].(map[string]any)
	}
	at[path[len(path)-1]] = replacement
}

func TestRetainedBindingIntegerOperands(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	raw, err := os.ReadFile(filepath.Join(root, "tests/fixtures/binding-host-integers/cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		ID, Fixture, Schema string
		Prepare             []struct {
			Path  []string
			Value json.RawMessage
		}
		FieldPath   []string        `json:"field_path"`
		HostValue   json.RawMessage `json:"host_value"`
		HostKind    string          `json:"host_kind"`
		SchemaValid bool            `json:"schema_valid"`
		Required    []string
		Clean       bool
	}
	if err = json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			check := func(v any) []string {
				t.Helper()
				valid, e := schema.ECL().Valid(c.Schema, v)
				if e != nil || valid != c.SchemaValid {
					t.Fatalf("schema: %v %v", valid, e)
				}
				found, e := bindings.EvaluateRecord(c.Schema, v)
				if e != nil {
					t.Fatal(e)
				}
				keys := []string{}
				rules := map[string]bool{}
				for _, f := range found {
					keys = append(keys, f.RuleID+"@"+f.Path)
					rules[f.RuleID] = true
				}
				sort.Strings(keys)
				for _, rule := range c.Required {
					if !rules[rule] {
						t.Fatalf("missing %s: %v", rule, keys)
					}
				}
				if c.Clean && len(keys) != 0 {
					t.Fatalf("clean control: %v", keys)
				}
				return keys
			}
			load := func() any {
				data, e := os.ReadFile(filepath.Join(root, c.Fixture))
				if e != nil {
					t.Fatal(e)
				}
				v, e := strict.Parse(data)
				if e != nil {
					t.Fatal(e)
				}
				for _, change := range c.Prepare {
					x, e := strict.Parse(change.Value)
					if e != nil {
						t.Fatal(e)
					}
					hostIntegerSet(v, change.Path, x)
				}
				return v
			}
			var baseline []string
			if c.SchemaValid {
				baseline = check(load())
			}
			modes := []string{"float64"}
			if c.HostKind == "whole-float" {
				modes = append(modes, "decimal-number", "exponent-number")
			}
			for _, mode := range modes {
				t.Run(mode, func(t *testing.T) {
					v := load()
					var operand any
					if mode == "float64" {
						if e := json.Unmarshal(c.HostValue, &operand); e != nil {
							t.Fatal(e)
						}
					} else {
						suffix := ".0"
						if mode == "exponent-number" {
							suffix = "e0"
						}
						operand = json.Number(string(c.HostValue) + suffix)
					}
					hostIntegerSet(v, c.FieldPath, operand)
					before := hostIntegerClone(v)
					found := check(v)
					if !reflect.DeepEqual(v, before) {
						t.Fatal("caller input mutated")
					}
					if baseline != nil && !reflect.DeepEqual(found, baseline) {
						t.Fatalf("representation changed findings: %v != %v", found, baseline)
					}
				})
			}
		})
	}
}
