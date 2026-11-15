package bindings

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestMCPTerminalReasons(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	data, err := os.ReadFile(filepath.Join(root, "tests/fixtures/mcp-terminal-reasons/manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Schema string `json:"schema"`
		Cases  []struct {
			ID          string   `json:"id"`
			Path        string   `json:"path"`
			Accepted    bool     `json:"accepted"`
			SchemaValid bool     `json:"schema_valid"`
			Rules       []string `json:"expected_rules"`
		} `json:"cases"`
	}
	if err = json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, item := range manifest.Cases {
		t.Run(item.ID, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, item.Path))
			if err != nil {
				t.Fatal(err)
			}
			decoder := json.NewDecoder(bytes.NewReader(data))
			decoder.UseNumber()
			var value any
			if err = decoder.Decode(&value); err != nil {
				t.Fatal(err)
			}
			before, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			findings, err := EvaluateRecord(manifest.Schema, value)
			if err != nil {
				t.Fatal(err)
			}
			rules := map[string]bool{}
			for _, finding := range findings {
				rules[finding.RuleID] = true
			}
			if !rules["ecl.error.schema-invalid.v1"] != item.SchemaValid {
				t.Fatalf("schema valid=%v findings=%+v", item.SchemaValid, findings)
			}
			if (len(findings) == 0) != item.Accepted {
				t.Fatalf("accepted=%v findings=%+v", item.Accepted, findings)
			}
			if len(rules) != len(item.Rules) {
				t.Fatalf("rule set differs: want %v got %+v", item.Rules, findings)
			}
			for _, rule := range item.Rules {
				if !rules[rule] {
					t.Fatalf("missing %s findings=%+v", rule, findings)
				}
			}
			after, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("record mutated")
			}
		})
	}
}
