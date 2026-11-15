package bindings

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMCPPublicReviewRepairs checks complete synthetic records through schema and binding.
func TestMCPPublicReviewRepairs(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	bytes, err := os.ReadFile(filepath.Join(root, "tests/fixtures/mcp-public-review-repairs/manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Schema string `json:"schema"`
		Cases  []struct {
			ID    string `json:"id"`
			Path  string `json:"path"`
			Valid bool   `json:"valid"`
			Rule  string `json:"expected_rule"`
		} `json:"cases"`
	}
	if err = json.Unmarshal(bytes, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, c := range manifest.Cases {
		t.Run(c.ID, func(t *testing.T) {
			bytes, err := os.ReadFile(filepath.Join(root, c.Path))
			if err != nil {
				t.Fatal(err)
			}
			var value any
			decoder := json.NewDecoder(strings.NewReader(string(bytes)))
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
			if c.Rule != "" {
				found := false
				for _, f := range findings {
					if f.RuleID == c.Rule {
						found = true
					}
				}
				if !found {
					t.Fatalf("missing rule %s: %+v", c.Rule, findings)
				}
			}
		})
	}
}
