package bindings

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func inputConsistencyRead(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "fixtures", "binding-input-consistency", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func inputConsistencyValue(t *testing.T, name string) any {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(inputConsistencyRead(t, name)))
	d.UseNumber()
	var value any
	if err := d.Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}
func TestBindingInputConsistency(t *testing.T) {
	var manifest struct {
		Cases []struct {
			ID, File, Schema string
			Rules            []string `json:"expected_rules"`
		}
	}
	if err := json.Unmarshal(inputConsistencyRead(t, "manifest.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	keys, err := LoadExportKeys(inputConsistencyRead(t, "export-keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range manifest.Cases {
		t.Run(item.ID, func(t *testing.T) {
			value := inputConsistencyValue(t, item.File)
			before, _ := json.Marshal(value)
			findings, err := EvaluateRecordWithKeys(item.Schema, value, keys)
			if err != nil {
				t.Fatal(err)
			}
			seen := map[string]bool{}
			rules := []string{}
			for _, f := range findings {
				if !seen[f.RuleID] {
					rules = append(rules, f.RuleID)
					seen[f.RuleID] = true
				}
			}
			sort.Strings(rules)
			if !reflect.DeepEqual(rules, item.Rules) {
				t.Fatalf("rules %v want %v; findings %v", rules, item.Rules, findings)
			}
			after, _ := json.Marshal(value)
			if !bytes.Equal(before, after) {
				t.Fatal("checker mutated input")
			}
		})
	}
}
func TestStrictJWSSegmentProfile(t *testing.T) {
	var manifest struct {
		Cases []struct{ ID, Base64, Expected string }
	}
	if err := json.Unmarshal(inputConsistencyRead(t, "strict-segments.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	for _, item := range manifest.Cases {
		t.Run(item.ID, func(t *testing.T) {
			raw, err := base64.StdEncoding.DecodeString(item.Base64)
			if err != nil {
				t.Fatal(err)
			}
			_, err = ParseStrictSegment(raw)
			result := "accept"
			if err != nil {
				result = "strict"
				if errors.Is(err, errRepeatedMember) {
					result = "duplicate"
				} else if !errors.Is(err, errNotStrict) {
					t.Fatalf("unexpected error %v", err)
				}
			}
			if result != item.Expected {
				t.Fatalf("got %s want %s", result, item.Expected)
			}
		})
	}
}
func TestJCSIJSONNoncharacters(t *testing.T) {
	scalars := []rune{}
	for cp := rune(0xfdd0); cp < 0xfdf0; cp++ {
		scalars = append(scalars, cp)
	}
	for p := 0; p < 17; p++ {
		scalars = append(scalars, rune(p*65536+65534), rune(p*65536+65535))
	}
	for _, cp := range scalars {
		for slot, value := range map[string]any{"key": map[string]any{string(cp): 1}, "value": map[string]any{"a": string(cp)}} {
			t.Run(fmt.Sprintf("%s-U+%04X", slot, cp), func(t *testing.T) {
				if _, err := JCS(value); !errors.Is(err, ErrJCS) {
					t.Fatalf("got %v, want ErrJCS", err)
				}
			})
		}
	}
}
func TestJCSJSONNumberGrammarAndValidScalars(t *testing.T) {
	for _, raw := range []string{"+42", "007", "1_000.5", "0x1.8p+1"} {
		if _, err := JCS(json.Number(raw)); !errors.Is(err, ErrJCS) {
			t.Fatalf("%s: %v", raw, err)
		}
	}
	for raw, want := range map[string]string{"42": "42", "1.5": "1.5", "-0": "0", "1e3": "1000"} {
		got, err := JCS(json.Number(raw))
		if err != nil || string(got) != want {
			t.Fatalf("%s: %s %v", raw, got, err)
		}
	}
	value := map[string]any{"\ue000": 1, "\U00010000": 2, "scalar": "🔑", "values": []any{1.5, json.Number("-0"), 1e21, 1e-7}}
	got, err := JCS(value)
	want := `{"scalar":"🔑","values":[1.5,0,1e+21,1e-7],"𐀀":2,"":1}`
	if err != nil || string(got) != want {
		t.Fatalf("%s %v", got, err)
	}
}
func TestExportKeyIdentifierCodepoints(t *testing.T) {
	for _, id := range []string{"k", strings.Repeat("k", 256), strings.Repeat("🔑", 129), strings.Repeat("🔑", 256)} {
		if _, err := NewExportKey(id, make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"", strings.Repeat("k", 257), strings.Repeat("🔑", 257)} {
		if _, err := NewExportKey(id, make([]byte, 32)); !errors.Is(err, ErrExportKeys) {
			t.Fatalf("expected controlled key error, got %v", err)
		}
	}
}
func TestMissingAfterSnapshotDirectFinding(t *testing.T) {
	value := inputConsistencyValue(t, "missing-after-otel-valid-failed-export-evidence-unchanged.json").(map[string]any)
	for _, f := range checkOTel(value, nil) {
		if f.RuleID == "ecl.rule.otel-export-after-evidence.v1" {
			return
		}
	}
	t.Fatal("missing after snapshot was not diagnosed")
}
