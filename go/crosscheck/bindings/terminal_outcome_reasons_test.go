package bindings

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAARMTerminalOutcomeReasons(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	data, err := os.ReadFile(filepath.Join(root, "tests/fixtures/terminal-outcome-reasons/manifest.json"))
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

func TestPairedTerminalOutcomeReasons(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	data, err := os.ReadFile(filepath.Join(root, "tests/fixtures/terminal-outcome-reasons/manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Cases []struct {
			ID      string   `json:"id"`
			Path    string   `json:"path"`
			Outcome *string  `json:"response_outcome"`
			Paired  bool     `json:"paired"`
			Rules   []string `json:"expected_rules"`
		} `json:"helper_cases"`
	}
	if err = json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, row := range manifest.Cases {
		t.Run(row.ID, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, row.Path))
			if err != nil {
				t.Fatal(err)
			}
			decoder := json.NewDecoder(bytes.NewReader(data))
			decoder.UseNumber()
			var record map[string]any
			if err = decoder.Decode(&record); err != nil {
				t.Fatal(err)
			}
			terminal := record["terminal"].(map[string]any)
			before, _ := json.Marshal(terminal)
			outcome := ""
			if row.Outcome != nil {
				outcome = *row.Outcome
			}
			found := TerminalReasonFindings(terminal, outcome, row.Paired)
			rules := map[string]bool{}
			for _, item := range found {
				rules[item.RuleID] = true
				if item.Path != "/extensions" {
					t.Fatalf("wrong relative path: %+v", item)
				}
			}
			if len(rules) != len(row.Rules) {
				t.Fatalf("want %v, got %+v", row.Rules, found)
			}
			for _, rule := range row.Rules {
				if !rules[rule] {
					t.Fatalf("missing %s: %+v", rule, found)
				}
			}
			after, _ := json.Marshal(terminal)
			if !bytes.Equal(before, after) {
				t.Fatal("terminal mutated")
			}
		})
	}
}
