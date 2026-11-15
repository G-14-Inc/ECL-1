package bindings

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestACSContextIdentity(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "fixtures", "acs-context-identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Schema string `json:"schema"`
		Cases  []struct {
			ID     string   `json:"id"`
			Record any      `json:"record"`
			Rules  []string `json:"expected_rules"`
		} `json:"cases"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err = decoder.Decode(&manifest); err != nil {
		t.Fatal(err)
	}
	for _, row := range manifest.Cases {
		t.Run(row.ID, func(t *testing.T) {
			before, err := json.Marshal(row.Record)
			if err != nil {
				t.Fatal(err)
			}
			found, err := EvaluateRecord(manifest.Schema, row.Record)
			if err != nil {
				t.Fatal(err)
			}
			rules := map[string]bool{}
			for _, item := range found {
				rules[item.RuleID] = true
			}
			if len(rules) != len(row.Rules) {
				t.Fatalf("want %v got %+v", row.Rules, found)
			}
			for _, rule := range row.Rules {
				if !rules[rule] {
					t.Fatalf("missing %s: %+v", rule, found)
				}
			}
			after, err := json.Marshal(row.Record)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("record changed")
			}
		})
	}
}
