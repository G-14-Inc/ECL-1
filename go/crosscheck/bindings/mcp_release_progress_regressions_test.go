package bindings

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMCPReleaseProgressRegressions preserves early refusals and partial recovery evidence.
func TestMCPReleaseProgressRegressions(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	data, err := os.ReadFile(filepath.Join(root, "tests/fixtures/mcp-release-progress-regressions/manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Schema string `json:"schema"`
		Cases  []struct {
			ID    string   `json:"id"`
			Path  string   `json:"path"`
			Valid bool     `json:"valid"`
			Rules []string `json:"expected_rules"`
		} `json:"cases"`
	}
	if err = json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, c := range manifest.Cases {
		t.Run(c.ID, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, c.Path))
			if err != nil {
				t.Fatal(err)
			}
			var value any
			decoder := json.NewDecoder(strings.NewReader(string(data)))
			decoder.UseNumber()
			if err = decoder.Decode(&value); err != nil {
				t.Fatal(err)
			}
			findings, err := EvaluateRecord(manifest.Schema, value)
			if err != nil {
				t.Fatal(err)
			}
			if (len(findings) == 0) != c.Valid {
				t.Fatalf("valid=%v expected=%v findings=%+v", len(findings) == 0, c.Valid, findings)
			}
			for _, rule := range c.Rules {
				found := false
				for _, f := range findings {
					if f.RuleID == rule {
						found = true
					}
				}
				if !found {
					t.Fatalf("missing rule %s: %+v", rule, findings)
				}
			}
		})
	}
}
