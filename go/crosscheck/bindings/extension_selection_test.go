package bindings

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"externalcontrollayer.ai/ecl-1/go/crosscheck/evidence"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/internal/validatorx"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/strict"
	"externalcontrollayer.ai/ecl-1/go/crosscheck/trust"
)

func TestExtensionSelectionRecords(t *testing.T) {
	root := filepath.Join("..", "..", "..", "tests", "fixtures", "extension-selection-cases")
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	var manifest struct {
		EvaluatedAt string `json:"evaluated_at"`
		Cases       []struct {
			ID, File, Kind, Schema string
			Accepted               bool
			RequiredCode           string `json:"required_code"`
		}
	}
	if err := json.Unmarshal(read("manifest.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	policy, err := trust.Load(read("bundle-trust.json"))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := LoadExportKeys(read("export-keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range manifest.Cases {
		t.Run(item.ID, func(t *testing.T) {
			value, err := strict.Parse(read(item.File))
			if err != nil {
				t.Fatal(err)
			}
			before, _ := json.Marshal(value)
			if item.Kind == "binding" {
				found, err := EvaluateRecordWithKeys(item.Schema, value, keys)
				if err != nil {
					t.Fatal(err)
				}
				if (len(found) == 0) != item.Accepted {
					t.Fatalf("accepted=%v wanted=%v: %+v", len(found) == 0, item.Accepted, found)
				}
				if !item.Accepted {
					matched := false
					for _, finding := range found {
						if finding.RuleID == item.RequiredCode {
							matched = true
						}
					}
					if !matched {
						t.Fatalf("required diagnostic %s absent: %+v", item.RequiredCode, found)
					}
				}
			} else {
				report, err := evidence.Verify(value, policy, evidence.Options{Now: manifest.EvaluatedAt})
				if err != nil {
					t.Fatal(err)
				}
				if (report.Verdict == "verified") != item.Accepted {
					t.Fatalf("wanted accepted=%v: %+v", item.Accepted, report)
				}
				if !item.Accepted {
					primary := evidence.PrimaryFinding(report)
					if primary == nil || *primary != item.RequiredCode {
						t.Fatalf("wanted primary %s: %+v", item.RequiredCode, report)
					}
				}
			}
			after, _ := json.Marshal(value)
			if string(before) != string(after) {
				t.Fatal("consumer mutated its input")
			}
		})
	}
}

func TestExtensionSelectionScope(t *testing.T) {
	entry := map[string]any{"id": "ecl.ext.outcome-reason.v1", "version": int64(1), "critical": false, "value": map[string]any{"code": "ecl.error.expired.v1"}}
	if !validatorx.InterpretedOccurrence(map[string]any{"protocol": "EBMP-2"}, entry) {
		t.Fatal("supported occurrence ignored")
	}
	if validatorx.InterpretedOccurrence(map[string]any{"protocol": "DCMP-2"}, entry) {
		t.Fatal("inapplicable occurrence interpreted")
	}
	for _, version := range []any{int64(2), true} {
		entry["version"] = version
		if validatorx.InterpretedOccurrence(map[string]any{"protocol": "EBMP-2"}, entry) {
			t.Fatal("unsupported occurrence interpreted")
		}
	}
}
